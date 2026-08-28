# Freewire VPN — Build and Release Pipeline

**Audience:** Engineers and DevOps  
**Version:** 1.0  
**Last updated:** 2026-06-17

---

## Overview

Freewire has three shippable artifacts:

1. **iOS app** — distributed via TestFlight at launch; App Store post-launch
2. **macOS app** — distributed via direct download (DMG) at launch; Mac App Store post-launch
3. **Server binary** — distributed as an AWS Marketplace AMI; not downloaded directly by users

---

## Version Numbering

All three artifacts share the same version number.

**Format:** `MAJOR.MINOR.PATCH` (semantic versioning)

- **MAJOR** — breaking protocol change; old clients cannot connect to new servers (triggers SYS-1 error in clients below `min_client_version`)
- **MINOR** — new features; backward compatible
- **PATCH** — bug fixes and security patches; no behavior change

**Build number:** An additional monotonically increasing integer used by Apple's App Store and TestFlight (`CFBundleVersion`). Increment on every build regardless of whether the version string changes. Never reset.

Example: version `1.2.3`, build `47`

---

## Repository Structure

Actual structure (matches `CLAUDE.md` §"Repository Structure"). There is **no
`ios/` directory and no `FreewireNE/` NetworkExtension target** — iOS and
NetworkExtension are deferred; macOS uses `wireguard-go` over `utun` directly, with
a Go helper binary for the transport carriers.

```
freewire/
├── macos/                  # macOS app (Swift)
│   ├── Freewire/           # App target (menu bar UI, settings, onboarding)
│   ├── FreewireHelper/     # Privileged helper (SMAppService) — pf kill switch. NOT YET BUILT
│   └── FreewireTests/
├── tunnel/                 # Go transport helper (freewire-tunnel, freewire-tokens)
│   └── cmd/
├── server/                 # Go server binary
│   ├── cmd/freewire-server/
│   ├── internal/
│   └── Makefile
└── .github/
    └── workflows/
```

Platform-shared client logic (fallback chain, Privacy Pass, API client, error
states) lives in the Go `tunnel/` helper and the Swift app, not a shared Swift
package. A `shared/` package and an `ios/` target return only when iOS resumes.

---

## CI/CD: GitHub Actions

All builds run on GitHub Actions. Branch strategy:

| Branch | Purpose | Builds triggered |
|---|---|---|
| `main` | Production-ready code | App Store / DMG release |
| `release/*` | Release candidates | TestFlight beta / macOS beta DMG |
| `develop` | Active development | Dev builds (internal only) |
| `feature/*` | Feature branches | PR builds (compile + test only) |

---

## iOS Build Pipeline

### Workflow: `.github/workflows/ios.yml`

**Triggers:** Push to `main` or `release/*`; manual dispatch

**Runner:** `macos-15` (Xcode 16+)

```yaml
steps:
  - name: Checkout
    uses: actions/checkout@v4

  - name: Select Xcode version
    run: sudo xcode-select -s /Applications/Xcode_16.app

  - name: Install dependencies
    run: |
      cd ios
      # WireGuardKit is a Swift Package dependency — no extra step needed

  - name: Increment build number
    run: |
      BUILD=$(date +%Y%m%d%H%M)
      xcrun agvtool new-version -all $BUILD

  - name: Run tests
    run: |
      xcodebuild test \
        -project ios/Freewire.xcodeproj \
        -scheme Freewire \
        -destination 'platform=iOS Simulator,name=iPhone 16'

  - name: Archive
    run: |
      xcodebuild archive \
        -project ios/Freewire.xcodeproj \
        -scheme Freewire \
        -archivePath build/Freewire-iOS.xcarchive \
        -configuration Release \
        CODE_SIGN_IDENTITY="Apple Distribution" \
        PROVISIONING_PROFILE_SPECIFIER="Freewire iOS Distribution"

  - name: Export IPA
    run: |
      xcodebuild -exportArchive \
        -archivePath build/Freewire-iOS.xcarchive \
        -exportPath build/ \
        -exportOptionsPlist ios/ExportOptions.plist

  - name: Upload to TestFlight (release/* branches)
    if: startsWith(github.ref, 'refs/heads/release/')
    run: |
      xcrun altool --upload-app \
        -f build/Freewire.ipa \
        -t ios \
        --apiKey ${{ secrets.APP_STORE_CONNECT_API_KEY_ID }} \
        --apiIssuer ${{ secrets.APP_STORE_CONNECT_ISSUER_ID }}

  - name: Submit to App Store (main branch, manual approval required)
    if: github.ref == 'refs/heads/main' && github.event_name == 'workflow_dispatch'
    run: |
      # App Store submission requires manual trigger to prevent accidental releases
      xcrun altool --upload-app \
        -f build/Freewire.ipa \
        -t ios \
        --apiKey ${{ secrets.APP_STORE_CONNECT_API_KEY_ID }} \
        --apiIssuer ${{ secrets.APP_STORE_CONNECT_ISSUER_ID }}
```

**Code signing:** Managed via Xcode's automatic signing with App Store Connect API key. Certificates and provisioning profiles are not stored in the repo — they are managed by Xcode's automatic signing.

**Required secrets:**
- `APP_STORE_CONNECT_API_KEY_ID`
- `APP_STORE_CONNECT_ISSUER_ID`
- `APP_STORE_CONNECT_PRIVATE_KEY` (the `.p8` file contents)

---

## macOS Build Pipeline

### Workflow: `.github/workflows/macos.yml`

**Triggers:** Push to `main` or `release/*`; manual dispatch

**Runner:** `macos-15`

```yaml
steps:
  - name: Archive
    run: |
      xcodebuild archive \
        -project macos/Freewire.xcodeproj \
        -scheme Freewire \
        -archivePath build/Freewire-macOS.xcarchive \
        -configuration Release \
        CODE_SIGN_IDENTITY="Developer ID Application: Freewire Inc (TEAMID)"

  - name: Export app bundle
    run: |
      xcodebuild -exportArchive \
        -archivePath build/Freewire-macOS.xcarchive \
        -exportPath build/ \
        -exportOptionsPlist macos/ExportOptions-DirectDownload.plist

  - name: Notarize
    run: |
      # Create zip for notarization
      ditto -c -k --keepParent build/Freewire.app build/Freewire.zip
      
      xcrun notarytool submit build/Freewire.zip \
        --apple-id ${{ secrets.APPLE_ID }} \
        --team-id ${{ secrets.APPLE_TEAM_ID }} \
        --password ${{ secrets.NOTARIZATION_APP_PASSWORD }} \
        --wait
      
      # Staple notarization ticket
      xcrun stapler staple build/Freewire.app

  - name: Create DMG
    run: |
      hdiutil create \
        -volname "Freewire" \
        -srcfolder build/Freewire.app \
        -ov -format UDZO \
        build/Freewire-${{ env.VERSION }}.dmg
      
      # Sign the DMG itself
      codesign --sign "Developer ID Application: Freewire Inc (TEAMID)" \
        build/Freewire-${{ env.VERSION }}.dmg

  - name: Upload DMG to CDN
    run: |
      aws s3 cp build/Freewire-${{ env.VERSION }}.dmg \
        s3://freewire-downloads/Freewire-${{ env.VERSION }}.dmg \
        --acl public-read
      
      # Update latest pointer
      aws s3 cp build/Freewire-${{ env.VERSION }}.dmg \
        s3://freewire-downloads/Freewire-latest.dmg \
        --acl public-read

  - name: Update Sparkle appcast
    run: |
      # See sparkle-update-feed-spec.md for appcast format
      python3 scripts/update_appcast.py \
        --version ${{ env.VERSION }} \
        --build ${{ env.BUILD_NUMBER }} \
        --dmg-path build/Freewire-${{ env.VERSION }}.dmg \
        --signing-key ${{ secrets.SPARKLE_ED_PRIVATE_KEY }}
```

**Notarization:** Required for all DMG releases. The build pipeline submits for notarization and staples the ticket before packaging the DMG. Gatekeeper rejects un-notarized builds on default macOS settings.

**Required secrets:**
- `APPLE_ID` — Apple ID used for notarization
- `APPLE_TEAM_ID`
- `NOTARIZATION_APP_PASSWORD` — app-specific password for the notarization Apple ID
- `SPARKLE_ED_PRIVATE_KEY` — EdDSA private key for signing Sparkle updates

---

## Server Build Pipeline

### Workflow: `.github/workflows/server.yml`

**Triggers:** Push to `main` or `release/*`; manual dispatch

**Runner:** `ubuntu-22.04`

```yaml
steps:
  - name: Set up Go
    uses: actions/setup-go@v5
    with:
      go-version: '1.23'

  - name: Run tests
    run: |
      cd server
      go test ./...

  - name: Build static binary
    run: |
      cd server
      CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
        go build -ldflags="-s -w -X main.Version=${{ env.VERSION }}" \
        -o freewire-server \
        ./cmd/freewire-server/

  - name: Upload to S3 (server releases bucket)
    run: |
      aws s3 cp server/freewire-server \
        s3://freewire-server-releases/${{ env.VERSION }}/freewire-server-linux-amd64
      
      # Update latest pointer (used by AMI auto-update)
      echo "${{ env.VERSION }}" | aws s3 cp - \
        s3://freewire-server-releases/latest
```

**AMI rebuild:** AMIs are rebuilt on major and minor version changes using a separate Packer workflow (`packer/aws-ami.pkr.hcl`). Patch releases update only the S3 binary (the running server auto-updates on next boot). AMI rebuild is manual-trigger only.

---

## Release Process

### Patch release (bug fix / security fix)

1. Merge fix to `develop`
2. Cut `release/1.x.y` branch from `develop`
3. CI builds TestFlight beta (iOS) and beta DMG (macOS)
4. Internal test: verify fix on TestFlight device and beta DMG
5. If clean: merge `release/1.x.y` to `main`
6. Manually trigger App Store submission workflow
7. Upload DMG to CDN (automated by pipeline on merge to `main`)
8. Update Sparkle appcast (automated)
9. App Store review: typically 24–48 hours for updates

### Minor release (new feature)

Same as patch, but also:
- Update App Store listing screenshots/description if UX changed
- TestFlight external beta testing (1 week minimum before App Store submission)

### Major release (breaking protocol change)

Same as minor, plus:
- Update `min_client_version` on managed servers **after** the new client version is live in the App Store (never before — old clients must still work during the transition window)
- Transition window: 30 days after major release before old clients are rejected
- Server-side: deploy new server binary, keep old protocol handler active during transition window

---

## Pre-Release Checklist

Run before every TestFlight / beta DMG submission:

- [ ] All tests pass (`xcodebuild test`, `go test ./...`)
- [ ] Build number incremented
- [ ] No known crash rate above 0.5% in current beta channel (check crash reports)
- [ ] Version string updated in all three targets (iOS, macOS, server)
- [ ] `min_client_version` in server config reviewed — no accidental increment
- [ ] Release notes written for TestFlight / App Store
- [ ] DMG notarization completes successfully (check CI logs)
- [ ] Sparkle appcast updated and accessible at `https://freewire.com/appcast.xml`

---

## Secrets Management

All CI secrets are stored in GitHub Actions repository secrets. The following must be configured before the first build:

| Secret | Used by | Description |
|---|---|---|
| `APP_STORE_CONNECT_API_KEY_ID` | iOS, macOS | App Store Connect API key ID |
| `APP_STORE_CONNECT_ISSUER_ID` | iOS, macOS | App Store Connect issuer ID |
| `APP_STORE_CONNECT_PRIVATE_KEY` | iOS, macOS | `.p8` API key file contents |
| `APPLE_ID` | macOS | Apple ID for notarization |
| `APPLE_TEAM_ID` | macOS | Apple Developer Team ID |
| `NOTARIZATION_APP_PASSWORD` | macOS | App-specific password for notarization Apple ID |
| `SPARKLE_ED_PRIVATE_KEY` | macOS | EdDSA private key for Sparkle update signing |
| `AWS_ACCESS_KEY_ID` | server, macOS | AWS credentials for S3 upload |
| `AWS_SECRET_ACCESS_KEY` | server, macOS | AWS credentials for S3 upload |

---

## uTLS Fingerprint Maintenance

The TLS/443 captive portal bypass path uses uTLS to mimic browser TLS fingerprints and avoid deep packet inspection. Browser fingerprints change with each major release.

**Update cadence:**
- Update the uTLS fingerprint library **quarterly** (aligned with Chrome/Safari release cycles)
- Trigger an **out-of-cycle update within 30 days** if a major Chrome or Safari/iOS release ships with a significantly different TLS fingerprint
- Rotate among 3 active fingerprint profiles: latest Chrome, latest Safari/iOS, latest Firefox — to reduce cross-user correlation

**Monitoring:**
- If TLS/443 success rate drops on captive portal networks without a corresponding network-side change, investigate whether a fingerprint update is needed
- Track uTLS library releases: https://github.com/refraction-networking/utls

**Process:** Update the uTLS library pin in `Package.swift`, run the TLS/443 captive portal test configs (configs 1–4 in `captive-portal-testing-guide.md`), and release as a patch update.
