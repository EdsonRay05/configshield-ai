"""Review Git-visible source for common credential markers without printing values."""
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'backend'))
from app.config import local_settings


def main():
    listing = subprocess.run(['git','-C',str(ROOT),'ls-files','--cached','--others','--exclude-standard','-z'], check=True, capture_output=True)
    paths = sorted(set(item.decode('utf-8') for item in listing.stdout.split(b'\0') if item))
    key = local_settings().get('GEMINI_API_KEY','')
    patterns = [rb'AIza[A-Za-z0-9_-]{30,}', rb'AQ\.[A-Za-z0-9_-]{25,}', rb'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----']
    matches = []
    inspected = 0
    for name in paths:
        path = ROOT / name
        if not path.is_file():
            continue
        content = path.read_bytes()
        inspected += 1
        if (len(key) > 12 and key.encode() in content) or any(re.search(pattern, content) for pattern in patterns):
            matches.append(name)
    ignored = subprocess.run(['git','-C',str(ROOT),'check-ignore','backend/.env'], capture_output=True).returncode == 0
    result = {'git_visible_files_inspected': inspected, 'credential_marker_matches': matches,
              'backend_env_ignored': ignored,
              'limitations': 'Checks known local key and selected credential signatures only; not an exhaustive secret detector.'}
    print(json.dumps(result,indent=2))
    return 1 if matches or not ignored else 0


if __name__ == '__main__':
    raise SystemExit(main())
