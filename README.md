# Secure Digital Document Vault
### Cryptography · Team 4 · Faculty of Engineering, UNAM · 2027-1

**English** · [Español](README.md)

A document vault that protects files with **authenticated encryption (AES-256-GCM)**, shares
them with multiple recipients using **elliptic-curve cryptography (ECIES secp256k1)**,
guarantees their origin with **digital signatures (Ed25519)**, and manages the **key
lifecycle** (registration, rotation and persistent revocation).

This version **integrates the whole system** into a single application (`app.py`) and a final
console demo (`demo_final.py`), both built on the same library (`vault/`).

---

## Contents

1. [Quick start](#quick-start)
2. [What the system guarantees](#what-the-system-guarantees)
3. [Security flow](#security-flow)
4. [The application (`app.py`)](#the-application-apppy)
5. [Final demo (`demo_final.py`)](#final-demo-demo_finalpy)
6. [Architecture](#architecture)
7. [Key repository and persistent revocation](#key-repository-and-persistent-revocation)
8. [`.vault` container format](#vault-container-format)
9. [Tests](#tests)
10. [Changes in the final version](#changes-in-the-final-version)
11. [Limitations](#limitations)
12. [Deliverables D2–D6](#deliverables-d2d6)
13. [Team](#team)

---

## Quick start

Requirements: **Python 3.12 or newer** (tested with 3.12.10) and, for the graphical interface, Tkinter.

### With the launcher (Linux, macOS and Windows with Git Bash/WSL)

```bash
./run.sh            # opens the integrated application
./run.sh demo       # final console demo (no graphical interface required)
./run.sh test       # 318 automated tests
./run.sh info       # platform, Python version and dependencies
./run.sh ayuda      # all commands (help)
```

`run.sh` looks for Python ≥ 3.12 (including the Windows `py` launcher), creates a `.venv`
virtual environment **specific to the current architecture and operating system** (x86_64,
arm64/Apple Silicon, armv7l, ppc64le, s390x, riscv64…), recreates it if it was copied from
another machine, installs `requirements.txt` only when it changes, and tells you which system
package is missing if something fails to compile. It accepts extra arguments:
`./run.sh app --tema oscuro`, `./run.sh test -v`.

### Manually with venv

```bash
python3.12 -m venv venv
source venv/bin/activate          # Windows PowerShell: venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py                     # graphical interface
python demo_final.py              # console demo
python -m pytest -q               # tests
```

If Tkinter is missing: `sudo apt install python3-tk` (Debian/Ubuntu), `sudo dnf install python3-tkinter`
(Fedora), `brew install python-tk@3.12` (macOS with Homebrew). On Windows it is included with the
official python.org installer.

---

## What the system guarantees

| Property | Mechanism |
|:---|:---|
| Confidentiality | AES-256-GCM with a random key and nonce per file |
| Per-recipient access | The file key is wrapped with ECIES (secp256k1) for each recipient |
| Content and metadata integrity | GCM tag + AAD covering the header and the full recipient list |
| Origin authenticity | Ed25519 signature over the SHA-256 of the **entire** container |
| Unsigned file = rejected | The integrated system never decrypts an unsigned `.vault` |
| Complete signature and key | Signature of exactly 64 bytes and a `signer_id` with the full SHA-256 (64 hex) |
| Persistent revocation | Encrypted on-disk history (scrypt + AES-256-GCM, atomic write with `fsync`) |
| Removal from the repository | Revoking deletes `ecies.keystore` and `firma.keystore` from disk |
| Private key protection | One keystore per key: scrypt (N=2¹⁵) + AES-256-GCM with authenticated metadata |

---

## Security flow

**Sending** — `Encrypt → Wrap key → Sign → Store`

1. The D6 history confirms that the signer is not revoked and that each recipient's public key
   is their **active** key (you cannot encrypt for a revoked identity).
2. AES-256-GCM encrypts the document once.
3. ECIES wraps the file key for each recipient.
4. Ed25519 signs the entire container, which is stored atomically.

**Receiving** — the order is fixed, with no shortcuts:

| Step | Check | On failure |
|:---:|:---|:---|
| 1 | The file **is signed** (unsigned → immediate rejection) | `ErrorFirma` |
| 2 | **Complete signature** (64 bytes, canonical Base64) **and valid** (Ed25519) | `ErrorFirma` |
| 3 | **Then the key**: `signer_id` = **full** SHA-256 of the signer's public key | `ErrorFirma` |
| 4 | D3 container format | `ContenedorInvalido` |
| 5 | The sender's signing key is **not revoked** | `FirmanteRevocado` |
| 6 | The recipient's ECIES key is the **active** one in the history | `ErrorCicloVida` |
| 7 | ECIES access + AES-GCM authentication → decryption | `DestinatarioNoAutorizado`, `InvalidTag` |

The recovered document is written only if all seven steps pass. If any of them fails, **no file
is written**.

---

## The application (`app.py`)

A macOS-style interface built with Tkinter only: sidebar, rounded cards, segmented controls,
modal sheets, tooltips and smooth transitions. The interface text is in Spanish.

* **Adapts to any computer**: automatic light/dark mode following the system (or forced with
  `--tema`), HiDPI scaling (enables *DPI awareness* on Windows), each system's native font
  (San Francisco, Segoe UI, Inter/Cantarell/Noto…), a grid that switches from 2 to 1 column in
  narrow windows, mouse-wheel scrolling on all three systems, and an initial size based on the
  screen (works from 800×600).
* **Startup**: asks for the key-history password (or creates it the first time). If it is wrong,
  the error is shown on the same screen.

| Section | What it does |
|:---|:---|
| **Identidades** (Identities) | Creates identities (or the 4 demo ones), shows their status (Active, Revoked, Unregistered), SHA-256 fingerprints (click to copy), unlocks/locks and **revokes**. |
| **Enviar** (Send) | Document → sender (signature) → one or more recipients → encrypted and signed `.vault`. Revoked identities are not offered as recipients. |
| **Recibir** (Receive) | Opens any `.vault`, identifies the sender by their `signer_id` in the local directory and shows the verification step by step (✓ / ✕). |
| **Laboratorio** (Lab) | Mallory's attacks on an in-memory copy: remove the signature, flip one bit, truncated signature, key with a truncated hash, sender impersonation, and Mallory as a non-recipient. |
| **Actividad** (Activity) | Security log of the session; can be exported to `.txt`. |

Private keys live in memory only while the identity is unlocked (**Bloquear sesión** / Lock
session discards them). The app does not store passwords.

Options: `python app.py --identidades OTHER_FOLDER --tema auto|claro|oscuro`
(also via the `VAULT_IDENTIDADES` and `VAULT_TEMA` environment variables).

**Suggested walkthrough for the presentation**

1. *Identidades* → **Crear alice, bob, carol y mallory** (create the demo identities).
2. *Enviar* → choose a document, sender **alice**, recipients **bob** and **carol**.
3. *Recibir* → open as **bob**: all 4 steps turn green.
4. *Laboratorio* → **Ejecutar todos** (run all): the 6 attacks are blocked.
5. *Identidades* → **Revocar** (revoke) bob, close the app and reopen it: he is still revoked and
   his keys are no longer in `identidades_demo/bob/`.
6. *Recibir* → opening as **carol** still works; revoking **alice** makes her file stop opening
   (*Remitente vigente* / sender still valid, shown in red).

---

## Final demo (`demo_final.py`)

Runs through the whole system in the console, using the same modules as the application, and
verifies 19 expected results (exit code 0 if all of them pass). It needs no graphical interface:
it works over SSH, on servers and in CI.

```bash
python demo_final.py                      # uses a temporary folder
python demo_final.py --carpeta output     # keeps the generated identities and .vault files
```

Stages: identities and persistent history → signed send to bob and carol → reception →
6 attacks + unsigned D3 file → persistent revocation of bob (restart, keystores deleted,
nobody can encrypt for bob, the restored key cannot be re-registered, carol keeps working) →
revocation of the signer alice.

The historical demos are still available: `python demo_d4_gui.py` (D3 without signatures, kept
only as a D4 reference) and `python demo_d5.py`.

---

## Architecture

```
app.py ──────────┐            demo_final.py ─────┐
                 ▼                               ▼
        vault/integrated_vault.py  (integrated-system facade)
          │            │                 │                 │
          ▼            ▼                 ▼                 ▼
  signed_sharing.py  key_lifecycle.py  keystore.py   persistencia.py
     │      │           (D6)             (D6)        (atomic writes)
     ▼      ▼
 signatures.py  sharing.py ── shared_container.py ── public_key.py
     (D5)          (D3)              (D3)               (D3, ECIES)
                     │
          encryption.py · decryption.py · key_management.py · container.py (D2)
```

| Module | Responsibility |
|:---|:---|
| `vault/integrated_vault.py` | Identities, public directory, send/receive, sender identification, revocation. |
| `vault/signed_sharing.py` | Encrypt → sign; verify signature → key → revocation → decrypt. |
| `vault/signatures.py` | Ed25519: what is signed, complete signature and `signer_id` with the full hash. |
| `vault/key_lifecycle.py` | Persistent D6 state: registration, rotation, history, revocation of ECIES and signing fingerprints. |
| `vault/keystore.py` | Encrypted private keys (scrypt + AES-256-GCM) and removal from the repository. |
| `vault/persistencia.py` | Atomic, durable writes (temporary file → `fsync` → `os.replace` → directory `fsync`). |
| `vault/ataques.py` | Simulated attacks shared by the app, the demo and the tests. |
| `vault/sharing.py`, `shared_container.py`, `public_key.py` | D3: multi-recipient container and ECIES. |
| `vault/encryption.py`, `decryption.py`, `key_management.py`, `container.py` | D2: password-based AES-256-GCM. |
| `vault/key_backup.py` | Keystore backup and restore. |

---

## Key repository and persistent revocation

```
identidades_demo/                 (excluded from git)
├── historial_claves.enc          encrypted D6 state: versions, history and revoked fingerprints
├── alice/
│   ├── ecies.keystore            ECIES secp256k1 private key (encrypted)
│   ├── firma.keystore            Ed25519 private key (encrypted)
│   └── publica.json              public directory: PEM + SHA-256 fingerprints
└── bob/ …
```

**Revoking an identity**:

1. Marks the record as `revocada` (revoked), stores the reason and adds **both fingerprints**
   (ECIES and signing) to the revocation list. The history is rewritten encrypted, with an atomic
   write and `fsync`, **before** anything else is touched (fails closed: if the disk fails, the
   revocation stays active in memory and a warning is raised).
2. Deletes `ecies.keystore` and `firma.keystore` from the repository (overwriting them with random
   bytes before deletion, as a best effort).
3. Keeps `publica.json` so the app can show that the identity is revoked.

Effects that **survive a restart**: nobody can encrypt for the revoked identity, it cannot
decrypt, files signed with its key are rejected, and a restored copy of its key **cannot be
registered again**.

The public directory is validated against its own fingerprints and against the encrypted
history: if someone replaces `publica.json`, the app detects it (`DirectorioAlterado`).

---

## `.vault` container format

```json
{
  "header": { "nombre_archivo": "...", "fecha": "...", "version": 3,
              "algoritmo": "AES-256-GCM", "algoritmo_envoltura": "ECIES-SECP256K1",
              "algoritmo_huella": "SHA256-SPKI-DER", "id_archivo": "..." },
  "recipients": [ { "id": "bob", "key_id": "<sha256 hex>", "encrypted_key": "<base64>" } ],
  "nonce": "...", "ciphertext": "...", "tag": "...",
  "signer_id": "<full sha256 hex of the Ed25519 public key>",
  "signature_algorithm": "ED25519-SHA256",
  "signature": "<64 bytes in base64>"
}
```

The signature covers `SHA-256(context || canonical JSON of the container without "signature")`,
so any change to the content, metadata, recipients, signer or algorithm invalidates it.

---

## Tests

```bash
python -m pytest -q          # or ./run.sh test
```

| File | Tests | Covers |
|:---|---:|:---|
| `test_encryption.py`, `test_decryption.py`, `test_container.py`, `test_key_management.py` | 30 | D2 |
| `test_public_key.py`, `test_shared_container.py`, `test_sharing.py` | 134 | D3 |
| `test_signatures.py`, `test_signed_sharing.py` | 67 | D5 |
| `test_keystore.py`, `test_key_backup.py`, `test_key_lifecycle.py` | 44 | D6 |
| `test_integrated_vault.py`, `test_revocacion_persistente.py` | 24 | D2–D6 integration |
| `test_sistema_integrado.py` | 18 | Final version: directory, attacks, signer revocation, re-registration |
| `test_demo_final.py` | 1 | End-to-end final demo |
| **Total** | **318** | |

GitHub Actions runs the tests and the final demo on Ubuntu, macOS and Windows with Python 3.12 and 3.13.

---

## Changes in the final version

**Requirements addressed**

* **Unsigned file → not decrypted**: the integrated system only opens signed `.vault` files;
  `identificar_remitente` immediately rejects a container without signature fields.
* **Always the signature first, then the key, both complete**: the exact 64-byte signature is
  verified first; then the `signer_id` with the full SHA-256; then the revocation status of the
  signer and of the recipient.
* **Persistent on-disk revocation**: encrypted history with atomic writes and `fsync`; a list of
  revoked fingerprints prevents re-registering a restored key.
* **The key leaves the repository**: revoking deletes `ecies.keystore` **and** `firma.keystore`.
* **`run.sh` launcher** for multiple platforms and architectures.
* **Integration in `app.py`**: identity creation (formerly `preparar_demo.py`), sending,
  receiving, attack lab, revocation and logging in a single application; new `demo_final.py`.

**Fixes and cleanup**

* The app no longer asks for the **recipient's** password to encrypt for them, nor for the
  sender's password to verify: it uses the public directory (`publica.json`), validated against
  the history.
* The app no longer keeps passwords in memory; it works with the unlocked keys.
* Wrong history password: it used to close the app with an unhandled error; now you can retry on
  the unlock screen.
* `historial_claves` existed but was never filled: it now stores rotated/revoked versions.
* Revocation of the signing key was added (`FirmanteRevocado`).
* A single atomic-write function (`vault/persistencia.py`) instead of three versions; `.vault`
  files are written with `fsync` and without orphaned temporary files.
* The history password policy now matches the keystore policy (when the history is created).
* Fingerprint comparisons run in constant time (`hmac.compare_digest`).
* Unused imports removed from `decryption.py`, `encryption.py` and `key_backup.py`.
* `preparar_demo.py` was removed: its functionality is now part of the application.

---

## Limitations

* Academic prototype; not intended for production use.
* The local public directory acts as the trusted channel; there is no PKI. To share across
  machines, verify fingerprints through an independent channel (`enviar_archivo_verificado`).
* Revoking a signer also invalidates the files it signed **before** the revocation (there is no
  trusted timestamping).
* Anyone who can delete `historial_claves.enc` and restore keystore backups can rebuild a keyring;
  the encrypted history prevents its **modification** without the password, not its deletion.
* Overwriting before deletion does not guarantee physical erasure on SSDs or copy-on-write
  filesystems; the real protection is the keystore encryption.
* Key rotation exists in `key_lifecycle.py`, but the app does not expose it yet.

---

## Deliverables D2–D6

| Deliverable | Content |
|:---|:---|
| D2 | Password-based (scrypt) AES-256-GCM symmetric encryption for a single owner. |
| D3 | Hybrid encryption: one file shared with multiple recipients using ECIES secp256k1. See [`docs/D3_HYBRID_DESIGN.md`](docs/D3_HYBRID_DESIGN.md). |
| D4 | Interactive demonstration and security review ([`docs/D4_Criptography.pdf`](docs/D4_Criptography.pdf)). |
| D5 | Ed25519 digital signatures over the full container (`D5 - Signatures & Authentication.pdf`). |
| D6 | Key management: keystores, backup, lifecycle and persistent revocation ([`docs/D6 - Key Management_T4.pdf`](docs/D6%20-%20Key%20Management_T4.pdf)). |

---

## Team

Universidad Nacional Autónoma de México · Faculty of Engineering · Cryptography · Group 4 · 2027-1

| Student ID | Team member | GitHub |
|:---|:---|:---|
| 319215555 | Alfaro Dominguez Arturo | @R2D2Alfa |
| 422526115 | Herrera Gallegos Karina Jezuleth | @Jezuleth |
| 422526067 | Sanchez Duran Dannae | @ddanae |
| 422534286 | Infante Martinez Javier de Jesus | @JavierInfanteB |
