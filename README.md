# Scourvex

Android cleaner and malware scanner with a neon UI. Built for a Galaxy S25 Ultra, but it runs on Android 11+.

## What it does

- **Clean**: app caches, thumbnail caches (including thumbnails of deleted photos), temp files, logs, ad/tracker folders, PC litter and empty folders, all in one tap. Recycle bins, hidden trash folders, leftovers of uninstalled apps, `LOST.DIR` and old installers are listed for you to tick first.
- **Security**: a real signature scan of every installed app and every file.
  - ClamAV hash and body signatures (Android, Linux and multi-OS families), rebuilt daily into `sigpack.zip`.
  - Stalkerware package and certificate indicators.
  - Optional live MalwareBazaar hash lookups, using your own free abuse.ch Auth-Key.
  - A permission risk audit: accessibility, device admin, SMS, hidden icons, sideloading.
- **Storage**: biggest files, folders and apps, a breakdown by type, and a duplicate finder (size → edge hash → full SHA-256).
- **Battery**: apps ranked by estimated mAh since the last full charge (Shizuku), or by screen-on time.
- **Skip list**: folders that are never scanned or cleaned.
- **Self-update**: from this repo's GitHub Releases.

## Shizuku (recommended)

Android 11+ blocks apps from `Android/data`, `Android/obb` and other apps' internal caches. With [Shizuku](https://shizuku.rikka.app/) running, Scourvex works as the shell user and can:

- clean those folders;
- trim every app's cache;
- read real battery stats;
- install updates silently.

To set it up:

1. Install Shizuku from the Play Store.
2. Turn on **Developer options → Wireless debugging**.
3. Press **Start** in Shizuku.
4. Allow Scourvex.

Shizuku has to be started again after every reboot. Without it, Scourvex runs in basic mode.

## Permissions

| Permission | Why |
|---|---|
| All files access | scan and clean storage |
| Usage access | size app caches; screen-on time fallback |
| Install unknown apps | self-update when Shizuku is off |
| Query all packages | scan every installed app |

## Build

```
./gradlew :app:testDebugUnitTest :app:assembleDebug
```

Release signing reads `keystore.properties` (never committed) or the `SCOURVEX_*` environment variables.

## Releases

- Pushing a `v*` tag builds a signed APK (`.github/workflows/release.yml`).
- The `sigpack` prerelease is rebuilt daily (`.github/workflows/sigpack.yml`). Set the repo secret `MB_AUTH_KEY` to also bundle MalwareBazaar Android sample hashes.

## Credits

- ClamAV signature databases © Cisco Talos, GPL-2.0.
- [stalkerware-indicators](https://github.com/AssoEchap/stalkerware-indicators) by Echap, CC BY 4.0.
- [MalwareBazaar](https://bazaar.abuse.ch/) by abuse.ch.
- Junk locations informed by [SD Maid SE](https://github.com/d4rken-org/sdmaid-se)'s open filter research.
