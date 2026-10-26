# Personal experimental LiveContainer + SideStore LoginFix build

This is an LLM-assisted personal integration, not a contribution submitted to the upstream maintainers. No upstream PR, issue or comment has been created. Do not describe it as an official release or as a proven login fix.

## Pinned inputs

The exact revisions and public base-package digest are recorded in `sources.json`.

- Host: the unmodified official LiveContainer + SideStore 3.8.11 package, with its existing LiveContainerSupport framework and host integration retained.
- SideStore source: `LiveContainer/SideStore` at `ee3cc16a67f9fed766f79a0ed70938f0f8ad5a07` on `LiveContainerSupport`. Its pairing changes are preserved.
- Authentication changes: the six auth-related Swift files changed by [PR #1683](https://github.com/SideStore/SideStore/pull/1683) through `3d9fcb68f6c4819269fb7836db590c4fda2efd84`.
- SideSign: the author's later reviewed revision `bfb637d939f8e36a92e6ca96f70e412f89d2b716`. The PR's pinned `ac3df50` still overwrites Mac headers with Windows headers, despite the newer SideStore code selecting Mac ADI. The later revision fixes that mismatch.
- The unrelated malformed Bonjour service strings from the PR are not copied. The build-only configuration sets `ALTAnisetteURL` to the matching Mac server.

## Build and verification

The `LoginFix experimental build` workflow first checks that the Mac identity regression fails against the original SideSign, then applies the pinned changes and runs the SideSign test suite. Tests use a local URLProtocol transport and synthetic values; they do not contact Apple or use an Apple account.

The packaging job converts the compiled SideStore executable with pinned upstream dylibify, retains LiveContainer's host integration, moves the widget to the host extension location, flattens nested framework code, and checks that the replacement OpenSSL exports the symbols used by the existing host. It removes provisioning profiles and old signatures, ad-hoc signs the staged code recursively, runs macOS `codesign --verify --deep --strict`, and independently verifies Mach-O CodeDirectory page hashes and archive structure.

The final IPA requires the user's own Windows-compatible signing tool and account. Build and archive verification cannot prove Apple sign-in or iPhone runtime compatibility. These scripts never connect to a device, replace an installed app, revoke certificates, or change pairing records.

The portable Python tests can be run on Windows with `LOGIN_FIX_BASE_IPA` pointing to the official combined base package:

```sh
python -m unittest discover -s loginfix/tests -p 'test_*.py' -v
```

## Current external blocker

The first GitHub Actions attempt did not start any build step: GitHub reported that the owner's account is locked due to a billing issue. No billing settings were changed. Until a macOS runner is available, Swift test results, native codesign verification and a rebuilt IPA remain unverified.

## Temporary publication

Publication to Nook is conditional on obtaining the verified final IPA and successfully testing both cutoff enforcement and storage expiration. The required cutoff is 2026-10-26 17:00:00 UTC (12:00 Colombia). Do not publish at or after the cutoff, publish an unbuilt replacement, or overwrite normal Nook installers and manifests. No temporary artifact has been published and no production removal schedule has been installed.

Authentication source and license terms remain those of the linked upstream repositories; the patch preserves their original file headers. The combined host retains LiveContainer's existing license.
