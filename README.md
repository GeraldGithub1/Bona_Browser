# BONA — Secure Web Browser

*"Bona" means **seeing** in Setswana.*

BONA is a desktop web browser for **Windows and Linux**, built on Electron 45 (Chromium engine).

## Install

| Platform | File | How |
|---|---|---|
| Windows 10/11 (64-bit) | `BONA-Setup-1.0.0.exe` | Double-click → choose folder → Install. Adds Desktop + Start Menu shortcuts and an uninstaller. |
| Linux (any distro) | `BONA-1.0.0-x86_64.AppImage` | `chmod +x BONA-1.0.0-x86_64.AppImage && ./BONA-1.0.0-x86_64.AppImage` |
| Ubuntu / Debian | `BONA-1.0.0-amd64.deb` | `sudo apt install ./BONA-1.0.0-amd64.deb` |

> The installer is not code-signed, so Windows SmartScreen will show "Windows protected your PC" →
> click **More info → Run anyway**. To remove this warning, buy a code-signing certificate and set
> `CSC_LINK` / `CSC_KEY_PASSWORD` before building.

## Security features

| Feature | What it does |
|---|---|
| **Sandboxed tabs** | Every tab runs in a Chromium sandbox with context isolation, no Node.js access, no `<webview>`, web security forced on. |
| **HTTPS-Only mode** | Upgrades every `http://` address and sub-resource to `https://`. If a site has no HTTPS, BONA warns and asks before using plain HTTP. |
| **BONA Shield (tracker blocker)** | Blocks ad networks, analytics, session-recorders, social pixels, data brokers and crypto-miners. Live count per page in the toolbar. |
| **Phishing guard** | Local checks for look-alike domains (e.g. `paypa1.com`, `fnb-secure-login.xyz`), brand-in-subdomain tricks, `@` URL tricks, punycode, raw-IP sites and scam TLDs. Includes SA banks (FNB, ABSA, Standard Bank, Nedbank, Capitec…) and SARS. Nothing is sent to any server. |
| **Certificate protection** | Invalid, expired or mismatched certificates are always blocked with a full-page warning. |
| **Permission control** | Camera, microphone, location, notifications, USB etc. are blocked unless you click **Allow**. Decisions can be reset from the Shield panel. |
| **Dangerous download warning** | Confirms before saving `.exe .msi .bat .ps1 .vbs .sh .apk .jar .docm` and other executable files. |
| **Private windows** | `Ctrl+Shift+N` — in-memory session, wiped when the window closes. |
| **Privacy headers** | Sends Do-Not-Track and Global Privacy Control. |
| **Third-party cookie blocking** | Optional (off by default because some logins need it). |
| **Clear data** | One click, or automatically every time BONA closes. |
| **Popup control** | Websites can never open raw windows; popups become normal tabs. |

## Keyboard shortcuts

`Ctrl+T` new tab · `Ctrl+W` close tab · `Ctrl+Tab` next tab · `Ctrl+L` address bar · `Ctrl+R`/`F5` reload ·
`Alt+←/→` back/forward · `Ctrl+N` new window · `Ctrl+Shift+N` private window · `Ctrl +/−/0` zoom ·
`Ctrl+P` print · `F11` full screen · `F12` developer tools

## Build from source

Requirements: Node.js 18+.

```bash
npm install
npm start              # run in development
npm run dist:win       # Windows installer  -> dist/BONA-Setup-1.0.0.exe
npm run dist:linux     # Linux AppImage+deb -> dist/
```

Building the Windows installer **on Linux** also needs Wine (`sudo apt install wine`).
On Windows, `npm run dist:win` works directly.

## Project layout

```
build/          icon.svg (master logo), icon.png, icon.ico, icons/ (Linux sizes)
src/main.js     windows, tabs, and all security enforcement
src/preload.js  minimal bridge for the browser UI only
src/ui/         browser chrome (tabs, toolbar, Shield/Downloads/Settings panels)
src/pages/      built-in pages: home (new tab), warning (phishing), error
src/security/   blocklist.js (tracker rules), url-check.js (phishing + download checks)
```

To add tracker domains, edit `src/security/blocklist.js`. To add brands to protect, edit the
`BRANDS` list in `src/security/url-check.js`.
