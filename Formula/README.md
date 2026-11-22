# Homebrew tap scaffold

In-repo formula for [ovh/shai#103](https://github.com/ovh/shai/issues/103). Users can tap this repository directly until a dedicated `homebrew-shai` tap or a `homebrew-core` submission exists.

## Install

Tap the repository that currently ships `Formula/shai.rb` (this fork until upstream merges it):

```bash
brew tap shaiss/shai https://github.com/shaiss/shai
brew install shai
```

After upstream adoption:

```bash
brew tap ovh/shai https://github.com/ovh/shai
brew install shai
```

## Updating after a release

1. Cut a GitHub Release that includes the expected assets (`shai-linux-x86_64`, `shai-linux-aarch64`, `shai-macos-x86_64`, `shai-macos-aarch64`, and optionally `shai-windows-x86_64.exe`).
2. Download each Unix asset and compute `shasum -a 256`.
3. Update `version`, each `url`, and each `sha256` in `Formula/shai.rb`.
4. When `shai-linux-aarch64` ships:
   - Replace the Linux ARM `on_arm` block with a binary `url`/`sha256` like the other platforms.
   - Remove the `depends_on "rust" => :build` that only exists for the source fallback.
   - Update `install` so Linux ARM uses the binary path (`bin.install "shai-linux-aarch64" => "shai"`) instead of `cargo install --path shai-cli`. Leaving `install` on the cargo path after switching the URL will fail because a naked binary download has no `shai-cli` crate.

## Maintainer notes

- `install.sh` still points at GitHub Releases; this formula is an alternative for environments that prefer Homebrew.
- Do not publish this package as `cargo install shai` on crates.io — that name is taken by an unrelated crate.
- Windows is not covered by Homebrew; use the Windows release asset (when published) or build from source.
