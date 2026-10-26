import os
import plistlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from audit_ipa import audit_ipa, verify_macho, validate_bundle_executables

BASE = Path(os.environ.get('LOGIN_FIX_BASE_IPA', r'C:\Users\Usuario\Downloads\LiveContainer-reparacion\LiveContainer+SideStore.ipa'))


class SignatureAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with zipfile.ZipFile(BASE) as archive:
            info = plistlib.loads(archive.read('Payload/LiveContainer.app/Info.plist'))
            cls.code = archive.read('Payload/LiveContainer.app/' + info['CFBundleExecutable'])

    def test_checks_real_arm64_executable_code_directory_hashes(self):
        result = verify_macho(self.code)
        self.assertTrue(result['valid'])
        self.assertEqual(result['cpu'], 0x0100000C)
        self.assertEqual(result['filetype'], 2)
        self.assertGreater(result['verified_pages'], 10)

    def test_rejects_modified_code_even_with_an_otherwise_valid_zip_crc(self):
        damaged = bytearray(self.code)
        damaged[8192] ^= 1
        with self.assertRaisesRegex(ValueError, 'code page'):
            verify_macho(damaged)

    def test_rejects_out_of_bounds_load_commands(self):
        damaged = bytearray(self.code)
        damaged[20:24] = (len(damaged) + 1).to_bytes(4, 'little')
        with self.assertRaisesRegex(ValueError, 'load command'):
            verify_macho(damaged)

    def test_rejects_archive_path_traversal_before_extracting(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'unsafe.ipa'
            with zipfile.ZipFile(path, 'w') as archive:
                archive.writestr('../outside', 'untrusted archive entry')
            with self.assertRaisesRegex(ValueError, 'Unsafe archive path'):
                audit_ipa(path)

    def test_rejects_a_declared_framework_executable_that_escaped_binary_validation(self):
        import io
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            archive.writestr('Payload/LiveContainer.app/Frameworks/Other.framework/Info.plist',
                             plistlib.dumps({'CFBundleExecutable':'Other'}))
            archive.writestr('Payload/LiveContainer.app/Frameworks/Other.framework/Other', b'unsupported code')
        with zipfile.ZipFile(buffer) as archive:
            with self.assertRaisesRegex(ValueError, 'Unvalidated bundle executable'):
                validate_bundle_executables(archive, set())


if __name__ == '__main__':
    unittest.main()
