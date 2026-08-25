# SecureVault

**Offline hardware password manager — ESP32 vault + web interface.**

SecureVault is a "cold wallet" style password manager. Instead of storing credentials in the cloud or in your browser, every password lives encrypted on a physical ESP32 device with an SD card. There is no internet connection, no server, and no sync — the only way in or out of the vault is a direct USB connection.

---
## Wev Interface to manage valut:
https://webvault.42web.io

## Why

Most password managers trade convenience for a bigger attack surface:

- Cloud-synced vaults turn a single breach into a mass credential leak.
- Browser-stored passwords are a common target for malware.
- Any internet-connected vault is, by definition, remotely reachable.

SecureVault removes the network entirely. If it isn't plugged in, it can't be reached.

---

## How It Works

```
ESP32 Vault  ──USB──  PC / Browser
(SD card, AES-256-GCM)      (Web Interface)
```

The ESP32 never releases or stores a credential without explicit confirmation. Every password is decrypted only in RAM, and the decryption key is wiped immediately after use.

---

## Architecture

### 1. Firmware (ESP32, C++)
- Encrypted credential store (`vault.db`) on an SD card
- **AES-256-GCM** encryption at rest
- Custom serial command protocol over USB
- Multi-account support per domain (unique key = `domain + username`, similar to how Google Password Manager handles multiple logins on one site)

### 2. Web Interface (HTML / JS)
- Master-password gated app shell
- Search, list, add, and generate credentials
- Connects to the ESP32 over WebSerial via USB
- Re-authentication required to view, edit, or delete any single entry

---

## Custom Serial Protocol

SecureVault does not use an existing password-manager protocol — the command set below was designed specifically for this vault:

| Command  | Description                                  |
|----------|-----------------------------------------------|
| `UNLOCK` | Authenticate with the master password         |
| `SAVE`   | Encrypt and store a new credential             |
| `GET`    | Return all accounts stored for a domain        |
| `LIST`   | List all unique stored sites                   |
| `DELETE` | Remove a credential by domain + username       |
| `LOCK`   | Wipe the decryption key from RAM, seal the vault |

---

## Security Design

- **AES-256-GCM encryption at rest** — every credential in `vault.db` is encrypted, never stored in plaintext, with built-in tamper detection via GCM's authentication tag.
- **RAM-only decryption** — credentials are decrypted only in memory; the key is wiped immediately after use.
- **Confirmation before release** — the ESP32 never hands over or stores a credential without explicit user confirmation.
- **Layered master password** — required to enter the app, and required again for any individual view/edit/delete action.
- **Zero network exposure** — no cloud sync, no server. The vault only ever talks to a directly-attached PC over USB.

---

## Hardware

- ESP32 microcontroller
- SD card module (no touchscreen or LCD required for core vault operation)

---

## Roadmap

-  **Chrome Extension (autofill)** — *Coming Soon*
- Dedicated enclosure & PCB
- Biometric unlock option

---

