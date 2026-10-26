"""Apply build-only configuration; no device or account access."""
import plistlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
path = root / 'AltStore/Info.plist'
info = plistlib.loads(path.read_bytes())
info['ALTAnisetteURL'] = 'https://new.ani.sidestore.io'
path.write_bytes(plistlib.dumps(info))
