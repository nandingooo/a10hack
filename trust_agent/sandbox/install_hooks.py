"""Install all three lifecycle hooks into an explicitly selected project."""
import argparse
import json
import sys
from pathlib import Path


def install(project):
    path = Path(project).resolve() / '.claude/settings.json'
    settings = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    hooks = settings.setdefault('hooks', {})
    script = Path(__file__).with_name('hook.py').resolve().as_posix()
    definition = {'matcher': '*', 'hooks': [{'type': 'command',
                  'command': f'"{sys.executable}" "{script}"', 'timeout': 10}]}
    for event in ('PreToolUse', 'PostToolUse', 'PostToolUseFailure', 'PermissionDenied'):
        groups = hooks.setdefault(event, [])
        # Replace only this exact hook, preserving unrelated hooks in the same group.
        for group in groups:
            group['hooks'] = [h for h in group.get('hooks', []) if script not in h.get('command', '').replace('\\', '/')]
        groups[:] = [g for g in groups if g.get('hooks')]
        groups.append(definition)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(settings, indent=2) + '\n', encoding='utf-8')
    print(path)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('project')
    install(parser.parse_args().project)
