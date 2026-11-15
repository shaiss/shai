#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: OVH SAS
#
# `curl` stand-in used by CI to run install.sh against binaries built in the
# same workflow run, so the script is tested before a release exists.
#
# Calls to the GitHub release API return a release whose only asset is
# "$STUB_ASSET_DIR/<asset name>" as a file:// URL. Every other call (the
# download itself) goes to the real curl, "$STUB_REAL_CURL".
#
# Asset names follow install.sh: shai-<platform> for the latest release,
# shai-<tag>-<platform> for a named tag such as "unstable".

for arg in "$@"; do
    case "$arg" in
        https://api.github.com/repos/*/releases/latest)
            name="shai-${STUB_PLATFORM}"
            ;;
        https://api.github.com/repos/*/releases/tags/*)
            name="shai-${arg##*/}-${STUB_PLATFORM}"
            ;;
        *)
            continue
            ;;
    esac
    printf '{"assets":[{"name":"%s","browser_download_url":"file://%s/%s"}]}\n' \
        "$name" "$STUB_ASSET_DIR" "$name"
    exit 0
done

exec "$STUB_REAL_CURL" "$@"
