#!/usr/bin/env bash
# Local macOS release build. Produces a DMG. Signs + notarizes + staples when a
# Developer ID Application certificate is present; otherwise builds UNSIGNED so
# the archive + packaging path is exercised now and this script "just works" the
# moment the certificate exists.
#
# Mirrors build-and-release-pipeline.md's macos.yml. Two deliberate differences:
#   - Real project path: macos/Freewire/Freewire.xcodeproj (the spec's
#     macos/Freewire.xcodeproj is wrong).
#   - S3/CDN upload and the Sparkle appcast update are release-DISTRIBUTION infra
#     (serving other people), which is out of the current single-user scope
#     (CLAUDE.md "Deferred until there are other users"). They are intentionally
#     not run here; the DMG is left in build/ for the operator.
#
#   scripts/release-macos.sh
#
# When a cert exists, also export for notarization:
#   APPLE_ID, APPLE_TEAM_ID, NOTARIZATION_APP_PASSWORD (app-specific password)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJ="$ROOT/macos/Freewire/Freewire.xcodeproj"
SCHEME="Freewire"
BUILD_DIR="$ROOT/build"
APP_NAME="Freewire.app"

setting() { xcodebuild -project "$PROJ" -scheme "$SCHEME" -showBuildSettings 2>/dev/null \
  | awk -F' = ' -v k="$1" '$1 ~ ("  "k"$"){print $2; exit}'; }
VERSION="$(setting MARKETING_VERSION | tr -d ' ')"; VERSION="${VERSION:-0.0.0}"
BUILD_NUM="$(setting CURRENT_PROJECT_VERSION | tr -d ' ')"; BUILD_NUM="${BUILD_NUM:-1}"

# A Developer ID Application identity gates signing. Absent -> unsigned dry run.
IDENTITY="$(security find-identity -v -p codesigning 2>/dev/null \
  | awk -F'"' '/Developer ID Application/{print $2; exit}')"
SIGN=0; [[ -n "$IDENTITY" ]] && SIGN=1

echo "==> Freewire macOS release: version $VERSION (build $BUILD_NUM)"
if [[ $SIGN == 1 ]]; then
  echo "    signing identity: $IDENTITY"
else
  echo "    NO Developer ID found -> DRY RUN: unsigned archive, DMG packaged, sign/notarize SKIPPED."
  echo "    Install the Developer ID Application cert and re-run for a signed+notarized DMG."
fi

rm -rf "$BUILD_DIR"; mkdir -p "$BUILD_DIR"
ARCHIVE="$BUILD_DIR/Freewire-macOS.xcarchive"
APP="$BUILD_DIR/$APP_NAME"

# Archive UNSIGNED and drive signing manually below. The app embeds helper
# binaries that must be signed BEFORE the app that contains them (codesign is
# inside-out), so letting xcodebuild sign the app during archive -- before the
# helpers are embedded -- would produce a bundle whose signature breaks the moment
# the helpers are added. Manual signing gives the correct nested order.
echo "==> archiving (Release, universal arm64+x86_64, unsigned; signing driven manually)"
# Capture rather than discard: a bare >/dev/null hid the compiler diagnostics, so
# an archive that failed on CI (a different Xcode than the developer's) reported
# only "ARCHIVE FAILED" with no way to see which files or why. On failure, print
# the errors and warnings before exiting.
ARCHIVE_LOG="$BUILD_DIR/xcodebuild-archive.log"
if ! xcodebuild archive -project "$PROJ" -scheme "$SCHEME" -configuration Release \
  -archivePath "$ARCHIVE" ARCHS="arm64 x86_64" ONLY_ACTIVE_ARCH=NO \
  CODE_SIGNING_ALLOWED=NO > "$ARCHIVE_LOG" 2>&1; then
  echo "ERROR: archive failed. Compiler diagnostics:" >&2
  grep -E 'error:|warning:' "$ARCHIVE_LOG" | grep -viE 'ld: warning|AppIntents' | tail -50 >&2
  echo "  (full log: $ARCHIVE_LOG)" >&2
  exit 1
fi
cp -R "$ARCHIVE/Products/Applications/$APP_NAME" "$APP"
[[ -d "$APP" ]] || { echo "ERROR: app bundle not produced at $APP" >&2; exit 1; }

# Embed the Go helper binaries. The app finds them next to its own executable
# (Contents/MacOS/, see TunnelManager.helperPath); a distributed release has no
# repo-path fallback, so an un-embedded release cannot run the tunnel at all.
# Built UNIVERSAL (arm64 + x86_64, lipo'd) so one DMG runs on Apple Silicon and
# Intel Macs alike -- matching the universal Swift app above.
echo "==> building + embedding universal helper binaries (freewire-tunnel, freewire-tokens)"
build_universal() { # $1 = ./cmd path (relative to tunnel/), $2 = output path
  ( cd "$ROOT/tunnel" \
    && GOOS=darwin GOARCH=arm64 go build -o "$2.arm64" "$1" \
    && GOOS=darwin GOARCH=amd64 go build -o "$2.amd64" "$1" )
  lipo -create "$2.arm64" "$2.amd64" -output "$2"
  rm -f "$2.arm64" "$2.amd64"
}
build_universal ./cmd/freewire-tunnel "$APP/Contents/MacOS/freewire-tunnel"
build_universal ./cmd/freewire-tokens "$APP/Contents/MacOS/freewire-tokens"
[[ -x "$APP/Contents/MacOS/freewire-tunnel" ]] || { echo "ERROR: helper embed failed" >&2; exit 1; }
echo "    app arch:    $(lipo -archs "$APP/Contents/MacOS/$SCHEME" 2>/dev/null)"
echo "    helper arch: $(lipo -archs "$APP/Contents/MacOS/freewire-tunnel" 2>/dev/null)"

if [[ $SIGN == 1 ]]; then
  echo "==> signing (hardened runtime; nested helpers first, then the app)"
  codesign --force --options runtime --timestamp --sign "$IDENTITY" "$APP/Contents/MacOS/freewire-tunnel"
  codesign --force --options runtime --timestamp --sign "$IDENTITY" "$APP/Contents/MacOS/freewire-tokens"
  codesign --force --options runtime --timestamp --sign "$IDENTITY" "$APP"
  codesign --verify --deep --strict "$APP" && echo "    signature verified"

  if [[ -n "${APPLE_ID:-}" && -n "${APPLE_TEAM_ID:-}" && -n "${NOTARIZATION_APP_PASSWORD:-}" ]]; then
    echo "==> notarizing"
    ditto -c -k --keepParent "$APP" "$BUILD_DIR/Freewire.zip"
    xcrun notarytool submit "$BUILD_DIR/Freewire.zip" \
      --apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" \
      --password "$NOTARIZATION_APP_PASSWORD" --wait
    xcrun stapler staple "$APP"
  else
    echo "==> notary creds not set (APPLE_ID/APPLE_TEAM_ID/NOTARIZATION_APP_PASSWORD); signed but NOT notarized."
  fi
fi

DMG="$BUILD_DIR/Freewire-$VERSION.dmg"
echo "==> creating DMG"
hdiutil create -volname "Freewire" -srcfolder "$APP" -ov -format UDZO "$DMG" >/dev/null
if [[ $SIGN == 1 ]]; then codesign --sign "$IDENTITY" "$DMG"; echo "    DMG signed"; fi

echo "==> done: $DMG"
ls -lh "$DMG" | awk '{print "    "$5"  "$NF}'
[[ $SIGN == 0 ]] && echo "    (unsigned dry run: Gatekeeper will reject this DMG -- it proves the packaging path only.)"
echo "    Distribution (S3/CDN, Sparkle appcast) intentionally not run -- single-user scope; see build-and-release-pipeline.md."
