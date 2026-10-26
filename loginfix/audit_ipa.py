"""Portable structural and CodeDirectory page-hash audit; not an iPhone launch test."""
import argparse
import hashlib
import io
import json
import plistlib
import struct
import zipfile
from pathlib import Path, PurePosixPath

MACHO_MAGIC = b'\xcf\xfa\xed\xfe'


def verify_macho(data):
    if len(data) < 32 or data[:4] != MACHO_MAGIC:
        raise ValueError('Expected a thin ARM64 Mach-O')
    _, cpu, subtype, filetype, commands, command_bytes, _, _ = struct.unpack_from('<8I', data)
    if cpu != 0x0100000C:
        raise ValueError('Non-ARM64 Mach-O in iOS package')
    if 32 + command_bytes > len(data):
        raise ValueError('Out-of-bounds load command region')
    offset, signature, dependencies, rpaths = 32, None, [], []
    for _ in range(commands):
        if offset + 8 > 32 + command_bytes:
            raise ValueError('Truncated load command')
        command, length = struct.unpack_from('<2I', data, offset)
        if length < 8 or offset + length > 32 + command_bytes:
            raise ValueError('Invalid load command length')
        if command == 0x1D:
            signature = struct.unpack_from('<2I', data, offset + 8)
        if command in (0xC, 0x80000018, 0x8000001F, 0x20, 0x80000023, 0x8000001C):
            string_offset = struct.unpack_from('<I', data, offset + 8)[0]
            if string_offset < 12 or string_offset >= length:
                raise ValueError('Invalid load command string')
            value = bytes(data[offset + string_offset:offset + length]).split(b'\0', 1)[0].decode('utf-8')
            (rpaths if command == 0x8000001C else dependencies).append(value)
        offset += length
    if offset != 32 + command_bytes:
        raise ValueError('Inconsistent load command region')
    if signature is None:
        raise ValueError('Mach-O has no code signature')
    signature_offset, signature_size = signature
    if signature_offset + signature_size > len(data) or signature_size < 12:
        raise ValueError('Invalid code signature bounds')
    signature_data = data[signature_offset:signature_offset + signature_size]
    magic, length, count = struct.unpack_from('>3I', signature_data)
    if magic != 0xFADE0CC0 or length > signature_size or 12 + count * 8 > length:
        raise ValueError('Invalid signature SuperBlob')
    pages, directories, cms, all_adhoc = 0, 0, False, True
    for index in range(count):
        kind, blob_offset = struct.unpack_from('>2I', signature_data, 12 + index * 8)
        if blob_offset + 8 > length:
            raise ValueError('Invalid signature blob offset')
        blob_magic, blob_length = struct.unpack_from('>2I', signature_data, blob_offset)
        if blob_length < 8 or blob_offset + blob_length > length:
            raise ValueError('Invalid signature blob length')
        if kind == 0x10000 and blob_length > 8:
            cms = True
        if blob_magic != 0xFADE0C02:
            continue
        blob = signature_data[blob_offset:blob_offset + blob_length]
        if len(blob) < 44:
            raise ValueError('Truncated CodeDirectory')
        version, flags, hash_offset, _, _, slots, code_limit = struct.unpack_from('>7I', blob, 8)
        hash_size, hash_type, _, page_shift = struct.unpack_from('4B', blob, 36)
        if version >= 0x20300 and code_limit == 0xFFFFFFFF:
            code_limit = struct.unpack_from('>Q', blob, 56)[0]
        if code_limit > signature_offset or hash_offset + slots * hash_size > len(blob) or page_shift > 30:
            raise ValueError('Invalid CodeDirectory code page bounds')
        hash_function = {1:hashlib.sha1, 2:hashlib.sha256, 3:hashlib.sha256, 4:hashlib.sha384}.get(hash_type)
        if not hash_function or hash_size not in (20, 32, 48):
            raise ValueError('Unsupported CodeDirectory hash algorithm')
        page_size = (1 << page_shift) if page_shift else code_limit
        if not page_size or slots != (code_limit + page_size - 1) // page_size:
            raise ValueError('Invalid CodeDirectory code page count')
        for slot in range(slots):
            page = data[slot * page_size:min((slot + 1) * page_size, code_limit)]
            actual = hash_function(page).digest()[:hash_size]
            expected = blob[hash_offset + slot * hash_size:hash_offset + (slot + 1) * hash_size]
            if actual != expected:
                raise ValueError(f'Invalid code page hash at page {slot}')
        pages += slots
        directories += 1
        all_adhoc = all_adhoc and bool(flags & 2)
    if not directories:
        raise ValueError('No CodeDirectory found')
    return {'valid':True, 'cpu':cpu, 'subtype':subtype, 'filetype':filetype,
            'verified_pages':pages, 'code_directories':directories, 'adhoc':all_adhoc,
            'cms_identity':cms, 'dependencies':dependencies, 'rpaths':rpaths}


def safe_entries(archive):
    seen = set()
    entries = archive.infolist()
    if len(entries) > 100000 or sum(entry.file_size for entry in entries) > 1024 ** 3:
        raise ValueError('Archive exceeds audit size limits')
    for entry in entries:
        path = PurePosixPath(entry.filename)
        if path.is_absolute() or '..' in path.parts or '\\' in entry.filename or ':' in entry.filename:
            raise ValueError('Unsafe archive path: ' + entry.filename)
        if entry.filename in seen:
            raise ValueError('Duplicate archive path: ' + entry.filename)
        seen.add(entry.filename)
    return entries


def validate_bundle_executables(archive, validated_paths):
    for entry in archive.infolist():
        if not entry.filename.endswith('/Info.plist'):
            continue
        info = plistlib.loads(archive.read(entry))
        executable = info.get('CFBundleExecutable')
        if not executable:
            continue
        path = str(PurePosixPath(entry.filename).parent / executable)
        if path not in validated_paths:
            raise ValueError('Unvalidated bundle executable: ' + path)


def audit_ipa(path):
    binaries = []
    with zipfile.ZipFile(path) as archive:
        entries = safe_entries(archive)
        bad = archive.testzip()
        if bad:
            raise ValueError('ZIP CRC mismatch: ' + bad)
        root = 'Payload/LiveContainer.app/'
        info = plistlib.loads(archive.read(root + 'Info.plist'))
        if info.get('CFBundleIdentifier') != 'com.kdt.livecontainer':
            raise ValueError('Unexpected LiveContainer bundle identifier')
        guest = root + 'Frameworks/SideStoreApp.framework/'
        guest_info = plistlib.loads(archive.read(guest + 'Info.plist'))
        if guest_info.get('CFBundleIdentifier') != 'com.SideStore.SideStore':
            raise ValueError('Unexpected embedded SideStore bundle identifier')
        for entry in entries:
            if entry.is_dir():
                continue
            if not entry.filename.startswith(root):
                raise ValueError('Unexpected file outside LiveContainer payload')
            if entry.filename.endswith('embedded.mobileprovision'):
                raise ValueError('Provisioning profile must not be distributed in the experimental IPA')
            data = archive.read(entry)
            if data[:4] != MACHO_MAGIC:
                continue
            if sum(part.endswith('.framework') for part in PurePosixPath(entry.filename).parts) > 1:
                raise ValueError('Nested framework code must be flattened: ' + entry.filename)
            result = verify_macho(data)
            if not result['adhoc'] or result['cms_identity']:
                raise ValueError('Stale certificate signature: ' + entry.filename)
            result['path'] = entry.filename
            binaries.append(result)
        by_path = {item['path']:item for item in binaries}
        validate_bundle_executables(archive, set(by_path))
        if by_path.get(root + info['CFBundleExecutable'], {}).get('filetype') != 2:
            raise ValueError('LiveContainer executable is missing or not MH_EXECUTE')
        if by_path.get(guest + guest_info['CFBundleExecutable'], {}).get('filetype') != 6:
            raise ValueError('Embedded SideStore is missing or not MH_DYLIB')
    return {'valid':True, 'version':info.get('CFBundleShortVersionString'),
            'sidestore_version':guest_info.get('CFBundleShortVersionString'),
            'bytes':Path(path).stat().st_size, 'sha256':hashlib.sha256(Path(path).read_bytes()).hexdigest(),
            'crc_verified':True, 'binaries':binaries, 'device_login_tested':False,
            'requires_personal_signing':True}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('ipa')
    parser.add_argument('--report')
    args = parser.parse_args()
    result = audit_ipa(args.ipa)
    output = json.dumps(result, indent=2)
    if args.report:
        Path(args.report).write_text(output + '\n', encoding='utf-8')
    print(output)
