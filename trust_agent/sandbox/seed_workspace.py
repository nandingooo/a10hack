"""Copy the explicit input snapshot to a writable volume; no host writes."""
import os
import shutil
from pathlib import Path

for path in Path('/input').iterdir():
    if path.name in ('.git','.claude'):
        continue
    dest = Path('/work') / path.name
    if path.is_dir():
        shutil.copytree(path,dest,dirs_exist_ok=True)
    else:
        shutil.copy2(path,dest)
for root, dirs, files in os.walk('/work'):
    os.chown(root,10001,10001)
    for name in files:
        os.chown(Path(root)/name,10001,10001)
Path('/identity/.claude').mkdir(parents=True,exist_ok=True)
os.chown('/identity',10001,10001)
os.chown('/identity/.claude',10001,10001)
os.chmod('/identity',0o700)
os.chmod('/identity/.claude',0o700)
