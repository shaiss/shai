# Homebrew tap scaffold

In-repo formula for [ovh/shai#103](https://github.com/ovh/shai/issues/103). Users can tap this repository directly until a dedicated `homebrew-shai` tap or a `homebrew-core` submission exists.

## Install

```bash
brew tap ovh/shai https://github.com/ovh/shai
brew install shai
```

## Updating after a release

1. Cut a GitHub Release that includes the expected assets (`shai-linux-x86_64`, `shai-linux-aarch64`, `shai-macos-x86_64`, `shai-macos-aarch64`, and optionally `shai-windows-x86_64.exe`).
2. Download each Unix asset and compute `shasum -a 256`.
3. Update `version`, each `url`, and each `sha256` in `Formula/shai.rb`.
4. When `shai-linux-aarch64` ships, replace the Linux ARM source-build block with a binary URL like the other platforms.

## Maintainer notes

- `install.sh` still points at GitHub Releases; this formula is an alternative for environments that prefer Homebrew.
- Do not publish this package as `cargo install shai` on crates.io — that name is taken by an unrelated crate.
- Windows is not covered by Homebrew; use the Windows release asset (when published) or build from source.
