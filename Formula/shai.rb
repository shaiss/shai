# Homebrew formula scaffold for Shai (addresses ovh/shai#103).
#
# Tap the repo that ships Formula/shai.rb:
#   brew tap shaiss/shai https://github.com/shaiss/shai
#   brew install shai
#
# After upstream merge, the same works with ovh/shai.
#
# After each GitHub Release, update `version`, each `url`, and each `sha256`
# below (see Formula/README.md). Linux aarch64 falls back to a source build
# until a release publishes `shai-linux-aarch64`.
class Shai < Formula
  desc "Terminal-based coding agent"
  homepage "https://github.com/ovh/shai"
  version "0.2.2"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "https://github.com/ovh/shai/releases/download/v#{version}/shai-macos-aarch64"
      sha256 "e4d6d1755b842a8b88c0426e61ea9b61f6f3f5feceff819f46135654964aaca6"
    end
    on_intel do
      url "https://github.com/ovh/shai/releases/download/v#{version}/shai-macos-x86_64"
      sha256 "86b51c7bd6eb567a8923fa543a86c8232d7fbf70906798eaf36b0d313f2d5903"
    end
  end

  on_linux do
    on_intel do
      url "https://github.com/ovh/shai/releases/download/v#{version}/shai-linux-x86_64"
      sha256 "445bf9b710f6b1f64b845f24ff0d4e39401cb552e578d525658ddadc6abb6779"
    end
    on_arm do
      # v0.2.2 has no shai-linux-aarch64 asset yet. main's release workflow
      # already builds it; after the next tagged release, switch this block
      # to the binary URL/sha256 like the other platforms.
      url "https://github.com/ovh/shai/archive/refs/tags/v#{version}.tar.gz"
      sha256 "d4defa2a4949a6e8fbf5eae0f40786478f709fe9aba993841da8838515d8ab6f"
      depends_on "rust" => :build
    end
  end

  def install
    if OS.linux? && Hardware::CPU.arm?
      system "cargo", "install", "--locked", "--root", prefix, "--path", "shai-cli"
    else
      asset = if OS.mac?
        Hardware::CPU.arm? ? "shai-macos-aarch64" : "shai-macos-x86_64"
      else
        "shai-linux-x86_64"
      end
      chmod 0755, asset
      bin.install asset => "shai"
    end
  end

  def caveats
    <<~EOS
      The crates.io name "shai" belongs to an unrelated project. Prefer this
      formula, install.sh, or `cargo install --path shai-cli` from a clone —
      not `cargo install shai`.
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/shai --version")
  end
end
