"""Image-build helper: install operator-controlled hooks in managed settings."""
import json
from pathlib import Path

hook = {'matcher': '*', 'hooks': [{'type':'command',
        'command':'python3 /opt/airlock/sandbox/hook.py', 'timeout':10}]}
settings = {'allowManagedHooksOnly':True, 'allowManagedPermissionRulesOnly':True,
            'disableAllHooks':False,
            'hooks':{event:[hook] for event in ('PreToolUse','PostToolUse','PostToolUseFailure','PermissionDenied')}}
Path('/etc/claude-code/managed-settings.json').write_text(json.dumps(settings))
