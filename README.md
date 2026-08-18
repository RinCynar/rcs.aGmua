# RCS.aGmua

RCS.aGmua is a cross-platform text utility built around the project's legacy RC4 format. It ships as a pure Python command-line tool and a Material You-style GUI powered by Tauri 2. The same web frontend is also available on the project website.

## Components

- `rcs_agmua/`: shared Python RC4 implementation, storage layer, update checker, and CLI.
- `web/`: browser and Tauri GUI. It implements encryption, decryption, key management, history, reset, update checks, and release downloads.
- `src-tauri/`: Tauri 2 shell for Windows and Android packages.
- `scripts/build_source_zip.py`: creates architecture-labelled Linux source archives.
- `.github/workflows/`: GitHub Pages deployment and GitHub Release artifact builds.

## Python CLI

The CLI uses only the Python standard library:

```bash
python -m rcs_agmua.cli -i
```

Commands:

```text
<text>           Encrypt text
- <hex>          Decrypt with all saved keys
- <hex> -<num>   Decrypt with one key
rak <key>        Add a key
rdk -<num>       Delete a key
rck              Display keys
rsh              Show history
rch              Clear history
res              Restore the default configuration
rcu              Check for updates
relp             Show help
rxit             Exit
```

The former brute-force command and its implementation have been removed.

## GUI and website

The GUI is the `web/` app packaged by Tauri. It stores browser data in `localStorage`; desktop and Android builds use the same local web storage provided by their WebView. No key or plaintext is sent to the GitHub Releases API.

Run the website directly with any static HTTP server, or open `web/index.html` during development. The root `index.html` keeps the old update response marker and redirects browsers to `web/`.

The Downloads view reads `https://api.github.com/repos/RinCynar/rcs.aGmua/releases/latest`. If that request fails, it falls back to the legacy `aGmua.dpdns.org` endpoint and links. The CLI uses the same GitHub-first, legacy-compatible fallback.

## Build the GUI

Install Node.js, Rust, and the Tauri prerequisites for the target operating system, then run:

```bash
npm install
npm run dev
npm run build
```

Windows targets:

```bash
npm run tauri build -- --target i686-pc-windows-msvc
npm run tauri build -- --target x86_64-pc-windows-msvc
npm run tauri build -- --target aarch64-pc-windows-msvc
```

Android APK targets:

```bash
npm run tauri android init
npm run tauri android build -- --apk --target i686
npm run tauri android build -- --apk --target x86_64
npm run tauri android build -- --apk --target armv7
npm run tauri android build -- --apk --target aarch64
```

Linux source archives:

```bash
python scripts/build_source_zip.py --platform linux --arch x86 --version 2.0.0 --output dist/rcs-agmua-gui-linux-x86-source.zip
python scripts/build_source_zip.py --platform linux --arch x64 --version 2.0.0 --output dist/rcs-agmua-gui-linux-x64-source.zip
python scripts/build_source_zip.py --platform linux --arch arm64 --version 2.0.0 --output dist/rcs-agmua-gui-linux-arm64-source.zip
```

The release workflow builds Windows executables, Android APKs, and Linux source ZIPs, then attaches them to a GitHub Release created from a `v*` tag.

## Compatibility and storage

The shared Python storage layer still understands the old raw `.rcs_keys` and `.rcs_hst` records. New records use a `v2:` base64 line format so binary ciphertext cannot corrupt newline-delimited history. The old username-derived filenames remain unchanged.

The published update response starts with the legacy `RCS <version>` marker and ends with a download URL. This lets old clients continue parsing the response while browsers use the new website.

## Security note

RC4 is obsolete and does not provide modern confidentiality or integrity guarantees. This project preserves RC4 for compatibility and educational use; do not use it for passwords, credentials, private messages, or other sensitive data. A future secure mode should use an authenticated modern cipher such as ChaCha20-Poly1305 or AES-GCM.

## License

MIT. See [LICENSE](LICENSE).
