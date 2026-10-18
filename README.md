
# Secure Digital Document Vault
### Cryptography · Team 4 · UNAM · 2027-1

Secure Digital Document Vault is an academic project developed for the Cryptography course at the Faculty of Engineering, UNAM.

The project focuses on protecting digital documents through modern cryptographic techniques.

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

The project includes 30 automated tests implemented with Pytest.

Run all tests from the project root directory:

```bash
python -m pytest -v
```

### Test Results

| Module | Tests | Result |
|:---|---:|:---|
| Encryption | 6 | Passed |
| Key Management | 9 | Passed |
| Container | 8 | Passed |
| Decryption | 7 | Passed |
| **Total** | **30** | **Passed** |

### Security Validation

The implementation includes tests for:

1. Successful encryption and decryption.
2. Rejection of incorrect keys or passwords.
3. Detection of modified ciphertext.
4. Detection of modified metadata.
5. Different ciphertexts from independent encryption operations.

**Result: 30 tests passed successfully.**

---

## Security Considerations

AES-256-GCM provides authenticated encryption, combining confidentiality and integrity protection.

Each file receives a fresh random encryption key and nonce. Reusing the same nonce with the same AES-GCM key can compromise security.

File metadata is authenticated using AAD, preventing unauthorized modifications from going undetected during decryption.

Cryptographic keys, nonces, and salts are generated using operating-system-provided secure randomness.

## Current Scope

This deliverable supports secure file encryption and decryption for a single owner.

The following features are outside the current scope:

- Multi-user access.
- Encrypted file sharing.
- Graphical user interface.
- Full security auditing.

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


