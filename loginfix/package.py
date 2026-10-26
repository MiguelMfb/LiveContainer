"""Package a compiled LiveContainerSupport SideStore on macOS without device access."""
import argparse
import hashlib
import json
import os
import plistlib
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

from audit_ipa import MACHO_MAGIC, audit_ipa, safe_entries


def tree_digest(path):
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    return [(str(item.relative_to(path)), hashlib.sha256(item.read_bytes()).hexdigest())
            for item in sorted(path.rglob('*')) if item.is_file()]


def flatten_frameworks(app):
    app = Path(app).resolve()
    root = app / 'Frameworks'
    for directory in sorted(app.rglob('Frameworks'), key=lambda item:len(item.parts), reverse=True):
        if directory == root:
            continue
        for item in list(directory.iterdir()):
            if not item.name.endswith(('.framework', '.dylib')):
                raise ValueError('Unexpected nested framework resource: ' + item.name)
            target = root / item.name
            if target.exists():
                if item.name == 'OpenSSL.framework':
                    old = plistlib.loads((target / 'Info.plist').read_bytes())
                    new = plistlib.loads((item / 'Info.plist').read_bytes())
                    if not str(old.get('CFBundleShortVersionString', '')).startswith('3.') or not str(new.get('CFBundleShortVersionString', '')).startswith('3.6.'):
                        raise ValueError('Unexpected OpenSSL ABI transition')
                    if not target.resolve().is_relative_to(app):
                        raise ValueError('Unsafe framework destination')
                    shutil.rmtree(target)
                elif tree_digest(item) == tree_digest(target):
                    if item.is_dir():
                        shutil.rmtree(item)
                    else:
                        item.unlink()
                    continue
                else:
                    raise ValueError('Conflicting framework: ' + item.name)
            shutil.move(str(item), str(target))
        directory.rmdir()


def run(*arguments):
    try:
        return subprocess.run([str(value) for value in arguments], check=True, capture_output=True).stdout
    except subprocess.CalledProcessError as error:
        raise RuntimeError(error.stderr.decode('utf-8', errors='replace')[-6000:]) from error


def extract(ipa, destination):
    with zipfile.ZipFile(ipa) as archive:
        safe_entries(archive)
        if archive.testzip():
            raise ValueError('Invalid source IPA CRC')
        archive.extractall(destination)


def binaries(app):
    result = []
    for item in app.rglob('*'):
        if not item.is_file():
            continue
        with item.open('rb') as stream:
            if stream.read(4) == MACHO_MAGIC:
                result.append(item)
    return result


def symbols(path, flags):
    return {line for line in run('xcrun', 'nm', flags, path).decode().splitlines() if line.startswith('_')}


def package(base, sidestore, dylibify, output):
    if sys.platform != 'darwin':
        raise RuntimeError('The final package requires macOS codesign, install_name_tool and dylibify')
    output = Path(output).resolve()
    with tempfile.TemporaryDirectory(prefix='livecontainer-loginfix-') as temporary:
        work = Path(temporary)
        extract(base, work / 'host')
        extract(sidestore, work / 'guest')
        app = work / 'host/Payload/LiveContainer.app'
        guest = app / 'Frameworks/SideStoreApp.framework'
        guest_config = (guest / 'LCAppInfo.plist').read_bytes()
        old_openssl = app / 'Frameworks/OpenSSL.framework/OpenSSL'
        old_exports = symbols(old_openssl, '-gUj')
        needed = set()
        for binary in binaries(app):
            if '.framework/Frameworks/' not in str(binary) and binary != old_openssl:
                needed.update(symbols(binary, '-uj') & old_exports)
        if not guest.resolve().is_relative_to(app.resolve()):
            raise ValueError('Unsafe staged guest path')
        shutil.rmtree(guest)
        shutil.move(str(work / 'guest/Payload/SideStore.app'), guest)
        (guest / 'LCAppInfo.plist').write_bytes(guest_config)
        converted = work / 'SideStore.dylib'
        run(Path(dylibify).resolve(), guest / 'SideStore', converted)
        if not converted.is_file():
            raise ValueError('dylibify did not create the embedded executable')
        os.replace(converted, guest / 'SideStore')
        widget = guest / 'PlugIns/AltWidgetExtension.appex'
        target_widget = app / 'PlugIns/LiveWidgetExtension.appex'
        if target_widget.exists():
            shutil.rmtree(target_widget)
        shutil.move(str(widget), target_widget)
        info_path = target_widget / 'Info.plist'
        widget_info = plistlib.loads(info_path.read_bytes())
        widget_info['CFBundleIdentifier'] = 'com.kdt.livecontainer.LiveWidget'
        widget_info['CFBundleExecutable'] = 'LiveWidgetExtension'
        info_path.write_bytes(plistlib.dumps(widget_info))
        (target_widget / 'AltWidgetExtension').rename(target_widget / 'LiveWidgetExtension')
        for name in ('Intents.intentdefinition', 'ViewApp.intentdefinition'):
            shutil.copy2(guest / name, app / name)
        intent_metadata = app / 'Metadata.appintents'
        if intent_metadata.exists():
            shutil.rmtree(intent_metadata)
        shutil.copytree(guest / 'Metadata.appintents', intent_metadata)
        actions = intent_metadata / 'extract.actionsdata'
        value = actions.read_bytes()
        value = value.replace(b'9SideStore20RefreshAllAppsIntentV', b'16SideStoreSupport20RefreshAllAppsIntentV')
        value = value.replace(b'9SideStore26RefreshAllAppsWidgetIntentV', b'16SideStoreSupport26RefreshAllAppsWidgetIntentV')
        actions.write_bytes(value)
        flatten_frameworks(app)
        missing = needed - symbols(old_openssl, '-gUj')
        if missing:
            raise ValueError('Replacement OpenSSL is missing required symbols: ' + ', '.join(sorted(missing)))
        rpaths = run('xcrun', 'otool', '-l', guest / 'SideStore').decode()
        if 'path @loader_path/.. ' not in rpaths:
            run('xcrun', 'install_name_tool', '-add_rpath', '@loader_path/..', guest / 'SideStore')
        # Export original public build entitlements before removing old signatures.
        entitlements = {}
        for info_path in app.rglob('Info.plist'):
            try:
                info = plistlib.loads(info_path.read_bytes())
            except plistlib.InvalidFileException:
                continue
            executable = info.get('CFBundleExecutable')
            if not executable or not (info_path.parent / executable).is_file():
                continue
            binary = info_path.parent / executable
            process = subprocess.run(['codesign', '-d', '--entitlements', ':-', str(binary)], capture_output=True)
            data = process.stdout
            if b'<?xml' in data:
                data = data[data.index(b'<?xml'):]
                parsed = plistlib.loads(data)
                if parsed:
                    file = work / ('entitlements-' + str(len(entitlements)) + '.plist')
                    file.write_bytes(plistlib.dumps(parsed))
                    entitlements[info_path.parent] = file
        for path in list(app.rglob('embedded.mobileprovision')):
            path.unlink()
        for path in sorted(app.rglob('_CodeSignature'), key=lambda item:len(item.parts), reverse=True):
            if not path.resolve().is_relative_to(app.resolve()):
                raise ValueError('Unsafe staged signature path')
            shutil.rmtree(path)
        for binary in binaries(app):
            binary.chmod(0o755)
            subprocess.run(['codesign', '--remove-signature', str(binary)], capture_output=True)
            run('codesign', '--force', '--sign', '-', '--timestamp=none', binary)
        bundles = sorted([item for item in app.rglob('*') if item.is_dir() and item.suffix in ('.framework', '.appex', '.app')], key=lambda item:len(item.parts), reverse=True)
        for bundle in [*bundles, app]:
            arguments = ['codesign', '--force', '--sign', '-', '--timestamp=none']
            if bundle in entitlements:
                arguments += ['--entitlements', str(entitlements[bundle])]
            run(*arguments, bundle)
        run('codesign', '--verify', '--deep', '--strict', '--verbose=2', app)
        (app / 'LoginFixSources.json').write_bytes((Path(__file__).parent / 'sources.json').read_bytes())
        # Resource additions precede the final root signature.
        arguments = ['codesign', '--force', '--sign', '-', '--timestamp=none']
        if app in entitlements:
            arguments += ['--entitlements', str(entitlements[app])]
        run(*arguments, app)
        run('codesign', '--verify', '--deep', '--strict', '--verbose=2', app)
        with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted((work / 'host/Payload').rglob('*')):
                archive.write(path, path.relative_to(work / 'host').as_posix())
    result = audit_ipa(output)
    result['macos_codesign_deep_strict_verified'] = True
    result['openssl_required_symbols_verified'] = len(needed)
    output.with_suffix('.verification.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({key:value for key, value in result.items() if key != 'binaries'}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('base')
    parser.add_argument('sidestore')
    parser.add_argument('dylibify')
    parser.add_argument('output')
    args = parser.parse_args()
    package(args.base, args.sidestore, args.dylibify, args.output)
