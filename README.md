
# Secure Digital Document Vault
### Cryptography · Team 4 · UNAM · 2027-1

Secure Digital Document Vault is an academic project developed for the Cryptography course at the Faculty of Engineering, UNAM.

The project focuses on protecting digital documents through modern cryptographic techniques.

---

## Deliverables

| Deliverable | Description |
|:---|:---|
| [D2](#d2--secure-symmetric-encryption-module) | Password-protected AES-256-GCM encryption for a single owner. |
| [D3](#d3--hybrid-encryption-and-secure-file-sharing) | Hybrid encryption: one encrypted file shared with multiple recipients. |

---

## D3 | Hybrid Encryption and Secure File Sharing

D3 extends the vault so that a file is **encrypted once** and shared with **multiple authorized recipients**. Only those recipients can decrypt it, even if the `.vault` container is publicly exposed.

The system uses **hybrid encryption**:

1. Generate a random 256-bit **file key**.
2. Encrypt the file once with **AES-256-GCM** (the AEAD from D2).
3. Encrypt (wrap) the file key separately with each recipient's **RSA public key** using **RSA-OAEP (SHA-256)**.
4. Store every wrapped key in the container, identified by the SHA-256 fingerprint of the recipient's public key.

Public keys are only ever used on the 32-byte file key, never on the file itself.

### Cryptographic Specifications (D3)

| Component | Implementation |
|:---|:---|
| File encryption | AES-256-GCM (AEAD) |
| Key wrapping | RSA-OAEP, SHA-256 / MGF1-SHA-256 |
| RSA key size | 3072 bits by default (minimum accepted: 2048) |
| Key identifier (`key_id`) | SHA-256 of the DER SubjectPublicKeyInfo of the public key |
| OAEP label | File ID + `key_id` + recipient ID (binds each wrapped key to its context) |
| AAD | Canonical JSON of the full header and the full ordered recipient list, with algorithm identifiers |
| Private key storage | Password-encrypted PKCS#8 PEM |
| Container | JSON `.vault`, format version 2 |

### Container Format

```json
{
  "header": { "nombre_archivo": "...", "fecha": "...", "version": 2,
              "algoritmo": "AES-256-GCM", "algoritmo_envoltura": "RSA-OAEP-SHA256",
              "algoritmo_huella": "SHA256-SPKI-DER", "id_archivo": "..." },
  "recipients": [
    { "id": "alice", "key_id": "<sha256 hex>", "encrypted_key": "<base64>" },
    { "id": "bob",   "key_id": "<sha256 hex>", "encrypted_key": "<base64>" }
  ],
  "nonce": "...",
  "ciphertext": "...",
  "tag": "..."
}
```

Adding, removing, reordering or modifying any recipient entry (or any header field) changes the AAD and makes decryption fail for everyone who does not hold the file key. See the limitations in the design document (no sender authentication, recipients are trusted with the file key).

### Usage

```python
from vault.public_key import generar_par_claves
from vault.sharing import compartir_archivo, abrir_archivo_compartido

alice = generar_par_claves()
bob = generar_par_claves()

# Encrypt once, share with Alice and Bob
compartir_archivo(
    "contrato.pdf",
    "contrato.vault",
    {"alice": alice.public_key(), "bob": bob.public_key()},
)

# Either recipient opens it with their own private key
datos = abrir_archivo_compartido("contrato.vault", bob, id_usuario="bob")
```

Before sharing, verify each public key against a fingerprint obtained through a trusted channel:

```python
from vault.public_key import huella_clave_publica, verificar_huella

print(huella_clave_publica(bob.public_key()))   # compare out of band
verificar_huella(bob.public_key(), huella_esperada)
```

### D3 Modules

| Module | Responsibility |
|:---|:---|
| `vault/public_key.py` | RSA key pairs, fingerprints, PEM import/export, RSA-OAEP wrap/unwrap. |
| `vault/shared_container.py` | Version 2 container format, strict validation, AAD construction. |
| `vault/sharing.py` | Multi-recipient encryption and recipient-based decryption. |

The D2 modules are unchanged; version 1 (password) containers continue to work.

### Documentation

See [`docs/D3_HYBRID_DESIGN.md`](docs/D3_HYBRID_DESIGN.md) for the hybrid design explanation, security decisions (key identification, recipient-list tampering, wrong public keys), known limitations and the requirement-to-test map.

---

## D2 | Secure Symmetric Encryption Module

This deliverable implements the cryptographic core of the Secure Digital Document Vault, providing secure file encryption and decryption for a single owner.

The implementation uses AES-256-GCM, an authenticated encryption algorithm that provides:

- Confidentiality of encrypted files.
- Integrity verification.
- Detection of unauthorized modifications.
- Authentication of file metadata.

### Cryptographic Specifications

| Component | Implementation |
|:---|:---|
| Encryption algorithm | AES-256-GCM (AEAD) |
| Encryption key | 256 bits (32 bytes) |
| Nonce | 96 bits (12 bytes) |
| Key derivation | Scrypt |
| Salt | 128 bits (16 bytes) |
| Metadata authentication | Additional Authenticated Data (AAD) |
| Secure randomness | `os.urandom()` |
| Output format | JSON-based `.vault` container |

---

## System Architecture

The system is organized into four independent modules:

| Module | Responsibility |
|:---|:---|
| `vault/encryption.py` | Encrypts file contents using AES-256-GCM. |
| `vault/key_management.py` | Generates and protects cryptographic keys. |
| `vault/container.py` | Creates, validates, stores, and reads encrypted containers. |
| `vault/decryption.py` | Decrypts files and verifies authentication. |

### Encryption Process

1. Read the original file.
2. Generate a fresh 256-bit encryption key and a random nonce.
3. Generate and authenticate file metadata using AAD.
4. Encrypt the file using AES-256-GCM.
5. Protect the encryption key using Scrypt and AES-GCM.
6. Store the encrypted information in a `.vault` container.

### Decryption Process

1. Read the encrypted container.
2. Recover the file encryption key using the owner's password.
3. Verify the authentication of the ciphertext and metadata.
4. Decrypt and recover the original file.

If authentication fails, the decryption operation is rejected.

---

## Installation

### Requirements

- Python 3
- cryptography
- pytest

Install the dependencies:

```bash
python -m pip install cryptography pytest
```

## Testing

The project includes 165 automated tests implemented with Pytest (30 from D2 and 135 from D3).

Run all tests from the project root directory:

```bash
python -m pytest -v
```

### Test Results

| Deliverable | Module | Tests | Result |
|:---|:---|---:|:---|
| D2 | Encryption | 6 | Passed |
| D2 | Key Management | 9 | Passed |
| D2 | Container | 8 | Passed |
| D2 | Decryption | 7 | Passed |
| D3 | Public Keys (`test_public_key.py`) | 20 | Passed |
| D3 | Shared Container (`test_shared_container.py`) | 77 | Passed |
| D3 | Sharing (`test_sharing.py`) | 38 | Passed |
| | **Total** | **165** | **Passed** |

### Security Validation

The D2 implementation includes tests for:

1. Successful encryption and decryption.
2. Rejection of incorrect keys or passwords.
3. Detection of modified ciphertext.
4. Detection of modified metadata.
5. Different ciphertexts from independent encryption operations.

The D3 implementation adds tests proving that:

1. A file shared with two users can be decrypted by both.
2. An unauthorized user cannot decrypt, even with the container in hand.
3. A tampered recipient list (added, renamed, reordered or modified entries) makes decryption fail.
4. A wrong private key fails.
5. Removing a recipient entry breaks access.
6. Public keys are only used on the 32-byte file key, and weak or non-RSA keys are rejected.
7. Malformed containers (unknown or duplicate fields, non-canonical Base64, look-alike recipient IDs) are rejected with a single error type.

**Result: 165 tests passed successfully.**

---

## Security Considerations

AES-256-GCM provides authenticated encryption, combining confidentiality and integrity protection.

Each file receives a fresh random encryption key and nonce. Reusing the same nonce with the same AES-GCM key can compromise security.

File metadata is authenticated using AAD, preventing unauthorized modifications from going undetected during decryption.

Cryptographic keys, nonces, and salts are generated using operating-system-provided secure randomness.

## Current Scope

D2 supports secure file encryption and decryption for a single owner with a password. D3 adds multi-user access and encrypted file sharing with hybrid encryption.

The following features are outside the current scope:

- Public-key authenticity infrastructure (a PKI or verified key directory); fingerprint verification is provided.
- Digital signatures (authentication between recipients).
- Revocation of access already granted (removing a recipient requires re-encrypting the file).
- Graphical user interface.
- Full security auditing.

See the limitations section of [`docs/D3_HYBRID_DESIGN.md`](docs/D3_HYBRID_DESIGN.md).

---

## Development Team

Universidad Nacional Autónoma de México  
Faculty of Engineering  
Cryptography · Group 4 · Semester 2027-1

| Student ID | Team Member | GitHub |
|:---|:---|:---|
| 319215555 | Alfaro Dominguez Arturo | @R2D2Alfa |
| 422526115 | Herrera Gallegos Karina Jezuleth | @Jezuleth |
| 422526067 | Sanchez Duran Dannae | @ddanae |
| 422534286 | Infante Martinez Javier de Jesus | @JavierInfanteB |

---


