"""Deterministic reference monitor with explicit execution and exposure state."""
import hashlib
import json
import ntpath
import posixpath
import re
import threading
import time
import uuid
import os
from pathlib import Path
from dataclasses import replace, asdict
from urllib.parse import urlsplit, unquote

from provenance import (ActionProps, Channel, ContextEntry, GraphStore, Kind, Labels,
                        Labeler, Op, Policy, Sensitivity, Trust, match)
from provenance import command
from lifecycle import Lifecycle, encode_entry, decode_entry


class Brain:
    def __init__(self, store=None, policy=None):
        self.store = store if store is not None else GraphStore()
        self.labeler = Labeler(policy or Policy.load())
        self.policy_digest=hashlib.sha256(json.dumps(asdict(self.labeler.cfg),sort_keys=True).encode()).hexdigest()
        self.state = Lifecycle(self.store)
        self.lock = threading.RLock()

    @staticmethod
    def path(target, cwd):
        module = ntpath if ntpath.splitdrive(cwd or target)[0] else posixpath
        return module.normpath(module.join(cwd or '/', target)).replace(chr(92), '/')

    def configure_session(self, session, allow_strengthening=False, **config):
        with self.lock, self.state.transaction():
            previous = self.state.get('session', session)
            config = dict(config, session_id=session, status='ACTIVE')
            if previous and previous != config:
                old_base={k:v for k,v in previous.items() if k!='ambient_secret'}
                new_base={k:v for k,v in config.items() if k!='ambient_secret'}
                if not (allow_strengthening and old_base==new_base and config.get('ambient_secret') is True):
                    raise ValueError('Session configuration is immutable; create a new session')
                self.state.log(session,dict(type='policy_strengthening',change='private_runtime_access_inference'))
            self.state.put('session', session, config)
            self.state.log(session, dict(type='session', **config))

    def sessions(self):
        with self.lock:
            return self.state.values('session')

    def events(self, session=None, after=0):
        with self.lock:
            return self.state.events(session, after)

    def kill(self, session):
        if not isinstance(session, str) or not session:
            raise ValueError('session_id required')
        with self.lock, self.state.transaction():
            config = self.state.get('session', session, {'session_id': session})
            config['status'] = 'KILLED'
            self.state.put('session', session, config)
            if hasattr(self.store, 'kill'):
                self.store.kill(session)
            self.state.log(session, dict(type='revocation', status='KILLED'))

    def _is_killed(self, session):
        return self.state.get('session', session, {}).get('status') == 'KILLED' or (
            hasattr(self.store, 'is_killed') and self.store.is_killed(session))

    def _profile(self, session, cwd):
        return self.state.get('session', session, dict(session_id=session, workspace_root=cwd,
                              workspace_id=cwd, repository_origin=self.labeler.cfg.default_origin,
                              strict=False, status='ACTIVE'))

    def _origin(self, target, profile):
        for rule in self.labeler.cfg.origin_rules:
            if match(target, rule['paths']):
                return rule['origin']
        return profile.get('repository_origin', self.labeler.cfg.default_origin)

    def _resource(self, profile, path):
        return [profile.get('workspace_id', profile['workspace_root']), path]

    def _entry(self, session, op, target, origin, channel, profile, basis='tool_result'):
        labels = self.labeler.label(target, origin)
        inherited = self.state.get('artifact', self._resource(profile, target))
        parents = []
        if inherited and op == 'ReadFile':
            labels = Labels(Trust.UNTRUSTED if inherited['trust'] == 'untrusted' or labels.effective_trust == Trust.UNTRUSTED else Trust.TRUSTED,
                            Sensitivity.SECRET if inherited['sensitivity'] == 'secret' or labels.sensitivity == Sensitivity.SECRET else labels.sensitivity,
                            labels.bait, labels.in_workspace, min(labels.confidence, inherited.get('confidence', 1)))
            parents = inherited['parents']
        kind = (Kind.SECRET if labels.sensitivity == Sensitivity.SECRET else Kind.SOURCE) if op in ('ReadFile', 'NetworkRequest') else Kind.ACTION
        return ContextEntry(id=f'{session}:{uuid.uuid4().hex}', ts=time.time(), session_id=session,
             kind=kind, channel=Channel(channel), op=Op(op), target=target, origin=origin, labels=labels,
             action_props=ActionProps() if kind == Kind.ACTION else None, parents=parents,
             metadata=dict(basis=basis, classification_reason='inherited_artifact' if inherited else 'source_policy_and_path',
                           workspace_id=profile.get('workspace_id'), execution_status='pending', exposure_status='pending'))

    def _context(self, session):
        entries = self.store.get_entries(session)
        evidence = [dict(id=e.id, target=e.target, trust=e.labels.effective_trust.value,
                         sensitivity=e.labels.sensitivity.value, parents=e.parents, **e.metadata)
                    for e in entries if e.kind != Kind.ACTION]
        secret = any(e['sensitivity'] == 'secret' for e in evidence)
        untrusted = any(e['trust'] == 'untrusted' for e in evidence)
        return entries, evidence, secret, untrusted

    def _pending(self, session):
        return [a for a in self.state.values('attempt') if a['session_id'] == session
                and a['verdict']['decision'] == 'allow' and a['status'] == 'pending'
                and a.get('entries')]

    @staticmethod
    def _inventory(profile):
        """Trusted guard observes workspace changes; file contents never enter the journal."""
        root = Path(profile['workspace_root'])
        if not root.is_dir():
            return {}
        result = {}
        for base, dirs, files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if d not in ('.git','node_modules','.venv','__pycache__')]
            for name in files:
                path = Path(base,name)
                try:
                    if path.is_symlink():
                        result[path.as_posix()] = 'symlink:' + os.readlink(path)
                    else:
                        digest = hashlib.sha256()
                        with path.open('rb') as handle:
                            for chunk in iter(lambda:handle.read(65536),b''):
                                digest.update(chunk)
                        result[path.as_posix()] = digest.hexdigest()
                except OSError:
                    result[path.as_posix()] = 'unreadable'
        return result

    def decide(self, req):
        with self.lock, self.state.transaction():
            return self._decide(req)

    def _decide(self, req):
        start = time.perf_counter()
        if not isinstance(req, dict):
            return self._v('block', 'invalid_request', 'Object required')
        session, op = req.get('session_id'), req.get('op')
        phase, args = req.get('phase', 'observed'), req.get('args', {})
        if not isinstance(session, str) or not session or not isinstance(op, str) or op not in {x.value for x in Op} or not isinstance(args, dict) or phase not in ('before', 'observed'):
            return self._v('block', 'invalid_request', 'Valid session, operation, arguments and phase required')
        if self._is_killed(session):
            return self._v('stop', 'session_killed', 'Session revoked')
        tool_id = req.get('tool_use_id')
        if phase == 'before' and (not isinstance(tool_id, str) or not tool_id):
            return self._v('block', 'invalid_request', 'tool_use_id required')
        key = [session, tool_id]
        fingerprint = hashlib.sha256(json.dumps(req, sort_keys=True).encode()).hexdigest()
        old = self.state.get('attempt', key) if phase == 'before' else None
        if old:
            if old['verdict'].get('policy_digest')!=self.policy_digest:
                return self._v('block','policy_changed','Policy changed since this attempt; create a new tool ID')
            return old['verdict'] if old['fingerprint'] == fingerprint else self._v('block', 'request_conflict', 'Tool ID reused for different input')
        cwd = req.get('cwd') or '/'
        if not isinstance(cwd, str) or not isinstance(req.get('target'), str):
            return self._v('block', 'invalid_request', 'String cwd and target required')
        profile = self._profile(session, cwd)
        channel = req.get('channel', 'hook')
        if channel not in {x.value for x in Channel}:
            return self._v('block', 'invalid_request', 'Unknown sensor channel')
        target = req['target']
        if op in ('ReadFile', 'WriteFile', 'DeleteFile', 'CopyFile', 'MoveFile'):
            target = self.path(target, cwd)
            if profile.get('strict') and Path(target).exists():
                target = Path(target).resolve().as_posix()
        origin = self._origin(target, profile)
        # Explicit origins are for trusted Python callers; managed HTTP sessions ignore them.
        if not profile.get('strict') and req.get('origin'):
            origin = req['origin']
        if op == 'NetworkRequest':
            origin = 'web'
        entry = self._entry(session, op, target, origin, channel, profile)
        entries, evidence, secret, untrusted = self._context(session)
        provisional = []
        cmd = str(args.get('command') or target) if op == 'RunCommand' else ''
        if cmd:
            for raw in dict.fromkeys(command.file_tokens(cmd)):
                path = self.path(raw, cwd)
                item = self._entry(session, 'ReadFile', path, self._origin(path, profile), channel, profile, 'shell_reference_inference')
                if item.labels.sensitivity == Sensitivity.SECRET or item.labels.effective_trust == Trust.UNTRUSTED:
                    provisional.append(item)
        inventory = self._inventory(profile) if cmd and profile.get('strict') else {}
        if cmd and profile.get('strict'):
            # Arbitrary interpreters can consume any readable workspace file. Do
            # not present regex references as a complete observation mechanism.
            known = {e.target for e in provisional}
            for path in inventory:
                if path not in known:
                    provisional.append(self._entry(session,'ReadFile',path,self._origin(path,profile),
                        channel,profile,'sandbox_access_inference'))
            if profile.get('ambient_secret'):
                private=self._entry(session,'ReadFile','/sandbox/private-runtime', 'workspace',
                    channel,profile,'private_runtime_access_inference')
                private=replace(private,labels=replace(private.labels,sensitivity=Sensitivity.SECRET))
                provisional.append(private)
        for item in provisional:
            evidence.append(dict(id=item.id, target=item.target, trust=item.labels.effective_trust.value,
                                 sensitivity=item.labels.sensitivity.value,
                                 basis='proposed_shell_reference' if item.metadata['basis']=='shell_reference_inference' else item.metadata['basis']))
            secret |= item.labels.sensitivity == Sensitivity.SECRET
            untrusted |= item.labels.effective_trust == Trust.UNTRUSTED
        unresolved = self._pending(session)
        if channel == 'egress':
            # A command's inferred inputs apply before its first outbound connection.
            for attempt in unresolved:
                for raw in attempt['entries']:
                    item = decode_entry(raw)
                    secret |= item.labels.sensitivity == Sensitivity.SECRET
                    untrusted |= item.labels.effective_trust == Trust.UNTRUSTED
                    evidence.append(dict(id=item.id, target=item.target, basis='inflight_operation',
                                         trust=item.labels.effective_trust.value, sensitivity=item.labels.sensitivity.value))
        urls = [target] if op == 'NetworkRequest' else re.findall(r'https?://[^\s\"\']+', cmd)
        hosts = command.hosts_in(cmd) if cmd else []
        if op == 'NetworkRequest':
            parsed = urlsplit(target if '://' in target else '//' + target)
            hosts = [(parsed.hostname or '').lower()]
        method = str(args.get('method', 'GET')).upper()
        upload = method not in ('GET','HEAD','OPTIONS','CONNECT') or bool(args.get('body')) or bool(re.search(r'(^|\s)(-d\b|--data\S*|-F\b|--form\b|-T\b|--upload-file\b|-X\s+(POST|PUT|PATCH))', cmd, re.I))
        encoded_channel = any(urlsplit(u if '://' in u else '//' + u).query for u in urls) or bool(args.get('headers'))
        opaque = channel == 'egress' and method == 'CONNECT'
        authorized_secret = bool(hosts) and all(any(match(h, [r['host']]) and r.get('max_sensitivity') == 'secret' and method in r.get('methods', []) for r in self.labeler.cfg.receivers) for h in hosts)
        root = profile['workspace_root'].rstrip('/')
        in_scope = target == root or target.startswith(root + '/')
        consequential = op in ('WriteFile','DeleteFile','MoveFile','CopyFile','RunCommand','CallTool','ModelCall','NetworkRequest')
        def permitted_resource(url):
            parsed=urlsplit(url if '://' in url else '//'+url)
            path=posixpath.normpath(unquote(unquote(parsed.path or '/')))
            for capability in profile.get('network_capabilities',[]):
                prefix=posixpath.normpath(capability.get('path_prefix','/'))
                if parsed.hostname==capability['host'] and method in capability.get('methods',[]) and (path==prefix or path.startswith(prefix.rstrip('/')+'/')):
                    return True
            return False
        permitted_upload=bool(urls) and all(permitted_resource(url) for url in urls)
        if self.labeler.is_bait_target(op, target, json.dumps(args)):
            self.kill(session)
            verdict = self._v('stop', 'bait_touched', 'Canary policy triggered; managed run must terminate')
        elif consequential and unresolved and channel != 'egress':
            verdict = self._v('block', 'unresolved_exposure', 'Earlier operation has no result; reconcile its exposure before consequential work')
        elif profile.get('strict') and op in ('WriteFile','DeleteFile','MoveFile','CopyFile') and not in_scope:
            verdict = self._v('block', 'workspace_boundary', 'Resource is outside the operator-authorized workspace')
        elif hosts and secret and (upload or encoded_channel or opaque) and not authorized_secret:
            verdict = self._v('block', 'secret_upload', 'Destination is not authorized for secret-bearing or opaque outbound data')
        elif profile.get('strict') and opaque and not authorized_secret:
            verdict = self._v('block','opaque_network','Encrypted destination has no operator-authorized data policy; use a modeled tool')
        elif profile.get('strict') and hosts and upload and not permitted_upload and not authorized_secret:
            verdict = self._v('block','task_boundary','Outbound write is outside the operator-authorized resource scope')
        elif any(not h or not self.labeler.approved_host(h) for h in hosts):
            verdict = self._v('block', 'secret_exit' if secret else 'lethal_trifecta' if untrusted else 'egress_allowlist', 'Unapproved destination')
        elif (op in ('DeleteFile','MoveFile') or command.is_destructive(cmd)) and untrusted and op not in profile.get('allowed_operations',[]):
            verdict = self._v('block', 'untrusted_destructive', 'Untrusted context may influence this destructive operation')
        elif op in ('CallTool','ModelCall') and target not in self.labeler.cfg.allowed_tools:
            verdict = self._v('block', 'unmodeled_tool', 'Tool needs an operator-defined policy')
        else:
            verdict = self._v('allow', 'read_recorded' if phase == 'observed' and op == 'ReadFile' else 'no_dangerous_flow', 'Operation satisfies current policy')
        verdict.update(evidence=evidence, evidence_basis='conservative_context_join', policy_version='exposure-v3',
                       policy_digest=self.policy_digest,
                       decision_id=uuid.uuid4().hex, latency_ms=round((time.perf_counter()-start)*1000, 3),
                       context=dict(untrusted=untrusted, secret=secret, unresolved=len(unresolved)))
        if any('inference' in e.get('basis','') or e.get('basis') in ('proposed_shell_reference','inflight_operation') or e.get('exposure_status')=='unknown' for e in evidence):
            verdict['confidence']=0.4 # inference heuristic, not a calibrated probability
        self.state.log(session, dict(type='decision', tool_use_id=tool_id, op=op,
            target='[shell command]' if cmd else target, **verdict))
        candidates = provisional + ([entry] if op in ('ReadFile','WriteFile','CopyFile','MoveFile','NetworkRequest') else [])
        for item in candidates:
            item.verdict, item.rule = verdict['decision'], verdict['rule']
        attempt = dict(session_id=session, tool_use_id=tool_id, fingerprint=fingerprint,
                       verdict=verdict, entries=[encode_entry(e) for e in candidates], status='pending',
                       op=op, target=target, profile=profile, inventory=inventory,
                       source=self.path(str(args.get('source','')),cwd) if args.get('source') else None)
        if phase == 'before':
            self.state.put('attempt', key, attempt)
        elif verdict['decision'] == 'allow':
            self._apply(attempt, success=True, exposure='exposed', execution='succeeded')
        return verdict

    def _apply(self, attempt, success, exposure, execution):
        session, profile = attempt['session_id'], attempt['profile']
        entries, _, secret, untrusted = self._context(session)
        parents = [e.id for e in entries if e.kind != Kind.ACTION]
        candidates = [decode_entry(e) for e in attempt['entries']]
        if attempt['op']=='RunCommand' and profile.get('strict'):
            for path, digest in self._inventory(profile).items():
                if attempt.get('inventory',{}).get(path) != digest:
                    candidates.append(self._entry(session,'WriteFile',path,self._origin(path,profile),
                        'hook',profile,'filesystem_change'))
        for item in candidates:
            if item.kind != Kind.ACTION:
                secret |= item.labels.sensitivity == Sensitivity.SECRET
                untrusted |= item.labels.effective_trust == Trust.UNTRUSTED
                parents.append(item.id)
        # Copy/move carry source labels even if the model has not inspected that source.
        source = attempt.get('source')
        if source:
            src = self._entry(session, 'ReadFile', source, self._origin(source,profile), 'hook', profile, 'artifact_transfer')
            secret |= src.labels.sensitivity == Sensitivity.SECRET
            untrusted |= src.labels.effective_trust == Trust.UNTRUSTED
            parents += src.parents
        for item in candidates:
            observed = item.kind != Kind.ACTION
            if observed and exposure == 'none':
                continue
            if not observed and not success and exposure=='none':
                continue
            metadata = dict(item.metadata, execution_status=execution, exposure_status=exposure)
            if not observed:
                labels = replace(item.labels, trust=Trust.UNTRUSTED if untrusted else item.labels.effective_trust,
                                 sensitivity=Sensitivity.SECRET if secret else item.labels.sensitivity)
                item = replace(item, labels=labels, parents=list(dict.fromkeys(item.parents + parents)), metadata=metadata)
                self.state.put('artifact', self._resource(profile,item.target), dict(trust=labels.effective_trust.value,
                    sensitivity=labels.sensitivity.value, parents=[item.id], confidence=0.4))
            else:
                item = replace(item, metadata=metadata)
            self.store.append(item)
        if success and attempt['op'] == 'MoveFile' and source:
            # Preserve old provenance as a tombstone; new path holds inherited labels.
            self.state.log(session, dict(type='artifact_move', source=source, target=attempt['target']))

    def complete(self, req):
        with self.lock, self.state.transaction():
            if not isinstance(req,dict) or not isinstance(req.get('session_id'),str) or not isinstance(req.get('tool_use_id'),str) or type(req.get('success')) is not bool:
                return self._v('block','invalid_result','Session, tool ID and boolean success required')
            key = [req['session_id'], req['tool_use_id']]
            attempt = self.state.get('attempt',key)
            if not attempt:
                return self._v('block','unknown_attempt','No matching attempt')
            if attempt['verdict']['decision'] != 'allow':
                return self._v('block','denied_attempt','Denied attempts cannot produce confirmed context')
            exposure = req.get('exposure', 'exposed' if req['success'] else 'unknown')
            if exposure not in ('none','exposed','unknown'):
                return self._v('block','invalid_result','Invalid exposure status')
            if attempt['profile'].get('strict') and attempt['op']=='RunCommand':
                # Arbitrary code has access to the session sensor credential. A
                # shell cannot downgrade its conservative exposure by reporting none.
                exposure='unknown'
            result = dict(success=req['success'], exposure=exposure, output_digest=req.get('output_digest'))
            if attempt['status'] == 'completed':
                return {'ok':True,'duplicate':True} if attempt['result'] == result else self._v('block','result_conflict','Completion changed on retry')
            self._apply(attempt, req['success'], exposure, 'succeeded' if req['success'] else 'failed')
            attempt.update(status='completed',result=result)
            self.state.put('attempt',key,attempt)
            self.state.log(req['session_id'],dict(type='result',tool_use_id=req['tool_use_id'],
                execution_status='succeeded' if req['success'] else 'failed',exposure_status=exposure,
                output_digest=req.get('output_digest')))
            return {'ok':True}

    def acknowledge_denial(self, req):
        with self.lock, self.state.transaction():
            session, tool=req.get('session_id'),req.get('tool_use_id')
            if not isinstance(session,str) or not isinstance(tool,str):
                return self._v('block','invalid_acknowledgment','Session and tool ID required')
            attempt=self.state.get('attempt',[session,tool])
            if not attempt or attempt['verdict']['decision'] not in ('block','stop'):
                return self._v('block','invalid_acknowledgment','No denied attempt to acknowledge')
            if not attempt.get('enforced'):
                attempt['enforced']=True
                self.state.put('attempt',[session,tool],attempt)
                self.state.log(session,dict(type='enforcement',tool_use_id=tool,
                    status='DENIED_BEFORE_EXECUTION',rule=attempt['verdict']['rule'],sensor_reported=True))
            return {'ok':True}

    @staticmethod
    def _v(decision,rule,reason):
        return dict(decision=decision,rule=rule,reason=reason,confidence=1.0)
