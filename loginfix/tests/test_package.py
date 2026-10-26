import plistlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from package import flatten_frameworks


def framework(path, version, code):
    path.mkdir(parents=True)
    (path / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleExecutable':'OpenSSL', 'CFBundleShortVersionString':version}))
    (path / 'OpenSSL').write_bytes(code)


class PackageLayoutTests(unittest.TestCase):
    def test_moves_nested_code_into_the_installers_framework_signing_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / 'LiveContainer.app'
            old = app / 'Frameworks/OpenSSL.framework'
            nested = app / 'Frameworks/SideStoreApp.framework/Frameworks/OpenSSL.framework'
            framework(old, '3.3.3001', b'old-host-library')
            framework(nested, '3.6.2000', b'new-sidestore-library')
            flatten_frameworks(app)
            self.assertEqual((old / 'OpenSSL').read_bytes(), b'new-sidestore-library')
            self.assertFalse(nested.exists())
            self.assertFalse(nested.parent.exists())

    def test_rejects_an_unexpected_conflicting_framework_instead_of_silently_replacing_it(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / 'LiveContainer.app'
            framework(app / 'Frameworks/Other.framework', '1.0', b'host')
            framework(app / 'Frameworks/SideStoreApp.framework/Frameworks/Other.framework', '2.0', b'guest')
            with self.assertRaisesRegex(ValueError, 'Conflicting framework'):
                flatten_frameworks(app)


if __name__ == '__main__':
    unittest.main()
