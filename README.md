\# Team 4 – Cryptography 2027-1



Repository for exercises, assignments, and documentation for our Cryptography course at UNAM.



\## Team Members



| Student ID | Name | GitHub Account |

|---|---|---|

| 319215555 | Alfaro Dominguez Arturo | @R2D2Alfa |

| 422526115 | Herrera Gallegos Karina Jezuleth | @Jezuleth |

| 422526067 | Sanchez Duran Dannae | @ddanae |

| 422534286 | Infante Martinez Javier de Jesus | @JavierInfanteB |



\## D2 – Secure Symmetric Encryption Module



This project implements the cryptographic core of the \*\*Secure Digital Document Vault\*\*, providing authenticated file encryption and decryption for a single owner.



The system uses \*\*AES-256-GCM\*\* to protect file confidentiality and integrity, including the detection of unauthorized modifications.



\### Cryptographic Design



\- \*\*Encryption algorithm:\*\* AES-256-GCM (AEAD).

\- \*\*File encryption key:\*\* Fresh 256-bit random key per file.

\- \*\*Nonce:\*\* Random 96-bit nonce generated for each encryption operation.

\- \*\*Key protection:\*\* Scrypt for password-based key derivation and AES-GCM for protecting the file key.

\- \*\*Metadata authentication:\*\* Additional Authenticated Data (AAD).

\- \*\*Secure randomness:\*\* Python's `os.urandom()`.

\- \*\*Output:\*\* JSON-based `.vault` container.



\### Project Modules



| Module | Description |

|---|---|

| `vault/encryption.py` | Encrypts file contents using AES-256-GCM. |

| `vault/key\_management.py` | Generates cryptographic keys and protects them using a password. |

| `vault/container.py` | Creates, stores, and reads encrypted containers. |

| `vault/decryption.py` | Recovers encrypted files and verifies authentication. |



\### Installation



Install the required Python dependencies:



```bash

python -m pip install cryptography pytest

```



\### Running Tests



From the project root directory, execute:



```bash

python -m pytest -v

```



The implementation includes \*\*30 automated tests\*\* covering encryption, decryption, key management, container handling, and tamper detection.



\### Security Tests



The tests verify:



1\. Successful encryption and decryption.

2\. Rejection of incorrect encryption keys.

3\. Detection of modified ciphertext.

4\. Detection of modified metadata.

5\. Different ciphertexts from independent encryption operations.



\### Current Scope



This deliverable supports encryption and decryption for a single file owner. File sharing and multi-user access are not implemented at this stage.

