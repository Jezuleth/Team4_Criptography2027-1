# D3 | Hybrid Encryption and Secure File Sharing

Design and security decisions for multi-recipient sharing in the Secure Digital Document Vault.

---

## 1. Hybrid Design Explanation

```text
File ──► AES-256-GCM (AEAD, from D2) ──► ciphertext + tag     (encrypted ONCE)

File key (32 random bytes)
   ├─► ECIES (secp256k1) with Alice's public key ──► encrypted_key (Alice)
   ├─► ECIES (secp256k1) with Bob's public key   ──► encrypted_key (Bob)
   └─► ECIES (secp256k1) with Carol's public key ──► encrypted_key (Carol)
```

### Why hybrid encryption is used

Public-key and symmetric encryption solve different problems:

| | Symmetric (AES-256-GCM) | Public-key (ECIES, secp256k1) |
|:---|:---|:---|
| Key distribution | Both sides need the same secret key | Anyone with a recipient's authentic public key can encrypt a secret that only the corresponding private key can recover |
| Data size | Efficient for files | Used here only for a short, fixed-size key payload |
| Integrity | Authenticates ciphertext and AAD | The ECIES implementation protects its encrypted payload; file and metadata authentication are handled by AES-GCM |

Hybrid encryption lets us distribute access without sharing an AES key beforehand while encrypting the file only once. Each recipient receives a separate ECIES-encrypted copy of the same 32-byte file key.

The function `envolver_clave()` in `vault/public_key.py` accepts **exactly 32 bytes** as its file-key input. It constructs a 64-byte ECIES plaintext: a 32-byte SHA-256 context digest followed by the 32-byte AES file key. Files themselves are never passed to ECIES.

### Why symmetric encryption is still needed

- AES-256-GCM efficiently encrypts file contents and authenticates the ciphertext and AAD.
- ECIES is used only to protect the small file-key payload, not the file contents.
- Encrypting the file once avoids storing a separate full ciphertext for every recipient. Each additional recipient adds one wrapped-key entry.

### Why per-recipient key encryption is required

- Each recipient has a distinct secp256k1 private/public key pair. An ECIES payload encrypted for one public key cannot normally be recovered with another private key.
- The same AES file key is encrypted separately for each recipient, while the file ciphertext is shared.
- ECIES encryption is randomized, so independent wrapped-key outputs differ even when protecting the same file key.
- Each encrypted key also includes a protected context digest binding it to the file ID, public-key fingerprint and recipient ID.

---

## 2. Container Format (version 3)

```json
{
  "header": {
    "nombre_archivo": "contrato.txt",
    "fecha": "2026-10-25T21:00:00+00:00",
    "version": 3,
    "algoritmo": "AES-256-GCM",
    "algoritmo_envoltura": "ECIES-SECP256K1",
    "algoritmo_huella": "SHA256-SPKI-DER",
    "id_archivo": "<16 random bytes, base64>"
  },
  "recipients": [
    { "id": "alice", "key_id": "<sha256 hex>", "encrypted_key": "<base64>" },
    { "id": "bob", "key_id": "<sha256 hex>", "encrypted_key": "<base64>" }
  ],
  "nonce": "<12 bytes, base64>",
  "ciphertext": "<base64>",
  "tag": "<16 bytes, base64>"
}
```

The D2 password-based container (version 1) is unchanged and remains supported by the existing D2 modules. The D3 sharing format is now version 3; previously generated version 2 RSA-OAEP containers are not automatically compatible with this ECIES format.

### What the AAD authenticates

```text
AAD = "D3-VAULT-AAD-v3\n" || canonical_json({ header, recipients })
```

`header` contains the format version, algorithm identifiers, file name, date and random `id_archivo`. `recipients` contains each entry (`id`, `key_id`, `encrypted_key`) **in order**. Canonical JSON (sorted keys, compact separators) makes AAD construction deterministic. AES-GCM detects unauthorized changes to these fields when the decryptor verifies the authentication tag.

### How ECIES binds each encrypted key to its context

For every recipient, `crear_etiqueta_envoltura()` builds a canonical JSON label with a domain-separation string (`D3-FILEKEY-ECIES-v1`), `id_archivo`, `key_id` and recipient ID. The sender calculates `SHA-256(label)` and encrypts the following payload using ECIES:

```text
ECIES plaintext = SHA-256(context label) || AES file key (32 bytes)
```

After ECIES decryption, `desenvolver_clave()` verifies that the payload is 64 bytes and compares the first 32 bytes to the expected context digest using a constant-time comparison. It returns the AES key only if the context matches. This is **not an RSA-OAEP label** or an ECIES library AAD parameter; it is an explicitly encrypted-and-checked context digest.

### Module layout

| Module | Responsibility |
|:---|:---|
| `vault/public_key.py` | secp256k1 key pairs, fingerprints, PEM import/export, ECIES wrap/unwrap and context verification |
| `vault/shared_container.py` | v3 format, strict validation, AAD construction, read/write |
| `vault/sharing.py` | High-level API: `cifrar_para_destinatarios`, `descifrar_como_destinatario` |

---

## 3. Security Decisions

### How do recipients identify their key?

Each recipient entry contains a `key_id`: the **SHA-256 digest of the DER SubjectPublicKeyInfo** encoding of that recipient's public key (full 256 bits, hexadecimal).

- **Deterministic:** the same public key produces the same `key_id`.
- **Derived, not declared:** on opening a file, the system derives the fingerprint from the supplied private key's public key instead of trusting a typed name alone.
- **No ambiguity:** duplicate recipient IDs or key IDs are rejected.
- **Optional identity check:** if `id_usuario` is provided, it must match the selected recipient entry.
- **Cryptographic context binding:** the ECIES-encrypted payload includes a digest of `{file ID, key_id, recipient ID}` and a fixed domain-separation string. Changing that context makes key recovery fail.

A fingerprint identifies a key, but does **not** independently prove who owns it. Its authenticity must be checked using a trusted channel.

### What happens if an attacker modifies the recipient list?

The full ordered recipient list, including wrapped keys, is authenticated as AES-GCM AAD. Unauthorized modifications make authentication fail for recipients who can otherwise recover the file key. Structural errors may be rejected even earlier by strict container validation. This guarantee assumes the attacker does not possess the AES file key.

| Attack | Result |
|:---|:---|
| Add a recipient entry | AES-GCM authentication fails (`InvalidTag`) |
| Remove a recipient entry | Removed user loses their entry; other recipients fail AAD authentication |
| Reorder entries | AES-GCM authentication fails (`InvalidTag`) |
| Change an `id` or `key_id` | Context verification, lookup or AES-GCM authentication fails |
| Modify or swap an `encrypted_key` | ECIES recovery or AES-GCM authentication fails |
| Copy an entry from another container | ECIES context verification fails because the file ID differs |
| Change an algorithm identifier or version | Strict validation rejects unsupported values (`ContenedorInvalido`) |
| Add unknown fields or duplicate JSON keys | Strict parser rejects the container (`ContenedorInvalido`) |
| Re-encode Base64 non-canonically | Strict validation rejects the container |
| Use invalid or confusable recipient IDs | Rejected by recipient-ID validation |

ECIES key wrapping occurs before the AAD is calculated. There is no circular dependency: each ECIES context digest depends on the file ID, key ID and recipient ID, while the final AES-GCM AAD also includes the resulting wrapped keys.

### What happens if the public key is wrong?

- **Wrong but valid public key:** if Mallory's secp256k1 public key is mistakenly registered as Bob's, the system cannot determine the true owner. Mallory may decrypt and Bob cannot. The caller must verify fingerprints through a trusted channel.
- **Unsupported key type or curve:** RSA public keys and elliptic-curve public keys other than secp256k1 are rejected before use.
- **Different private key:** a recipient who supplies a different private key has a different `key_id` and cannot find or decrypt the intended entry.

The project provides `verificar_huella()` for comparing a public key with a trusted fingerprint, but does not implement a PKI or verified key directory.

---

## 4. Known Limitations

- **The sender is not authenticated.** Anyone with public keys can create a new valid container. D3 protects confidentiality against non-recipients and detects unauthorized modification of an existing container; it does not prove who created the file. Digital signatures would help authenticate its origin.
- **Recipients know the file key.** An authorized recipient can decrypt, copy, re-share or potentially construct a modified container with a valid AES-GCM tag. The system does not prevent this.
- **No explicit key commitment.** AES-GCM does not inherently commit to a unique key. A malicious sender could potentially distribute different file keys or contents to different recipients. This design does not provide a cryptographic proof that every recipient sees identical plaintext from a malicious sender.
- **Metadata is not confidential.** File names, recipient IDs and public-key fingerprints are visible in the JSON container, although authenticated as AAD.
- **File names are untrusted input.** Callers must sanitize file names before using them as filesystem paths.
- **No retroactive revocation.** Removing a recipient requires creating a new container with a fresh file key; previously distributed copies and keys cannot be revoked.
- **Recipient-list changes require re-encryption.** The list is authenticated by AES-GCM, so modifying it requires producing a valid new container.
- **No public-key authenticity infrastructure.** Fingerprint verification requires a trustworthy out-of-band reference.
- **ECIES (secp256k1) is not post-quantum secure.** Its elliptic-curve security is vulnerable to sufficiently capable quantum computers. Replacing RSA-OAEP with ECIES does not provide post-quantum protection.
- **Private-key storage is the user's responsibility.** Private keys can be exported as password-encrypted PKCS#8 PEM. They must be stored and shared carefully; `.pem` and `.key` files should not be committed to Git.

---

## 5. Requirement → Test Map

| Requirement | Test (`tests/test_sharing.py` unless noted) |
|:---|:---|
| File shared with 2 users, both can decrypt | `test_archivo_compartido_con_dos_usuarios_ambos_descifran` |
| Unauthorized user cannot decrypt | `test_usuario_no_autorizado_no_puede_descifrar`, `test_usuario_no_autorizado_aunque_el_contenedor_sea_publico` |
| Tampered recipient list fails | `test_lista_de_destinatarios_alterada_hace_fallar_el_descifrado` (6 attacks), `test_alterar_la_propia_entrada_hace_fallar_el_descifrado` |
| Wrong private key fails | `test_clave_privada_incorrecta_falla`, `test_clave_privada_incorrecta_sobre_entrada_ajena`, `test_desenvolver_con_clave_privada_incorrecta` (`test_public_key.py`) |
| Removing a recipient entry breaks access | `test_eliminar_una_entrada_de_destinatario_rompe_el_acceso` |
| Key IDs deterministic | `test_huella_es_determinista` (`test_public_key.py`) |
| ECIES wraps only the short file key, not bulk file data | `test_no_se_pueden_envolver_datos_grandes` (`test_public_key.py`), `test_archivo_grande_no_pasa_por_ecies` |
| Wrong public key | `test_clave_publica_equivocada_da_acceso_a_la_persona_equivocada` |
| Unsupported key types and curves rejected | `test_rechaza_clave_publica_rsa`, `test_rechaza_curva_no_permitida` (`test_public_key.py`) |
| Strict container validation | `tests/test_shared_container.py` |
