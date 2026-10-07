"""Bundle authored code, dependency lock and measured report; never cloud state."""
from pathlib import Path
import zipfile
ROOT = Path(__file__).parent
with zipfile.ZipFile(ROOT / 'source.zip', 'w', zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(ROOT.rglob('*')):
        if not path.is_file() or any(x in path.parts for x in ('__pycache__', '.pytest_cache', '.venv', '.git')):
            continue
        if path.suffix in ('.zip', '.png', '.gz', '.xml') or path.name == 'deployment-state.json' or path.name.startswith('.env'):
            continue
        archive.write(path, path.relative_to(ROOT))
print('Source bundle bytes:', (ROOT / 'source.zip').stat().st_size)
