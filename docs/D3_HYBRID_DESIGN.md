# D3 | Hybrid Encryption and Secure File Sharing

Design and security decisions for multi-recipient sharing in the Secure Digital Document Vault.

---

## 1. Hybrid Design Explanation

```
File ──► AES-256-GCM (AEAD, from D2) ──► ciphertext + tag      (encrypted ONCE)

File key (32 random bytes)
   ├─► RSA-OAEP with Alice's public key ──► encrypted_key (Alice)
   ├─► RSA-OAEP with Bob's public key   ──► encrypted_key (Bob)
   └─► RSA-OAEP with Carol's public key ──► encrypted_key (Carol)
```

### Why hybrid encryption is used

Public-key and symmetric encryption each solve a different problem:

| | Symmetric (AES-GCM) | Public-key (RSA-OAEP) |
|:---|:---|:---|
| Key distribution | Both sides need the same secret in advance | Anyone can encrypt with a public key; only the private key holder decrypts |
| Data size | Any size, fast | Tiny messages only (RSA-2048 with OAEP-SHA256 fits at most 190 bytes) |
| Integrity | Built in (AEAD) | Not for bulk data |

Sharing a file needs both properties: *distribute access without a prior shared secret* (public key) and *handle files of any size* (symmetric). Hybrid encryption uses each for what it does well: the public-key layer protects one small key, and the symmetric layer protects the data.

The code enforces this boundary: `envolver_clave()` in `vault/public_key.py` refuses anything that is not exactly 32 bytes, so a file can never be passed to RSA.

### Why symmetric encryption is still needed

- RSA cannot encrypt a file: the OAEP message limit is far below any real document size.
- RSA alone gives no integrity over the file or its metadata. AES-256-GCM authenticates the ciphertext and the AAD, which is what detects tampering (D2).
- Encrypting the file once with a symmetric key keeps the container size roughly constant per recipient (one RSA block each), instead of one copy of the file per person.

### Why per-recipient key encryption is required

- Each person holds a different private key, and a ciphertext produced for one public key is unreadable with another. The same file key must therefore be wrapped separately for each recipient.
- The file itself is not duplicated: adding a recipient adds one entry, not another copy of the data.
- Each recipient only ever handles their own wrapped key. Nobody needs to receive a secret over another channel.
- OAEP is randomized, so the wrapped keys of different recipients look unrelated even though they protect the same file key.

---

## 2. Container Format (version 2)

```json
{
  "header": {
    "nombre_archivo": "contrato.txt",
    "fecha": "2026-10-25T21:00:00+00:00",
    "version": 2,
    "algoritmo": "AES-256-GCM",
    "algoritmo_envoltura": "RSA-OAEP-SHA256",
    "algoritmo_huella": "SHA256-SPKI-DER",
    "id_archivo": "<16 random bytes, base64>"
  },
  "recipients": [
    { "id": "alice", "key_id": "<sha256 hex>", "encrypted_key": "<base64>" },
    { "id": "bob",   "key_id": "<sha256 hex>", "encrypted_key": "<base64>" }
  ],
  "nonce": "<12 bytes, base64>",
  "ciphertext": "<base64>",
  "tag": "<16 bytes, base64>"
}
```

The D2 password-based container (version 1) is unchanged and still supported by the existing modules.

### What the AAD authenticates

```
AAD = "D3-VAULT-AAD-v2\n" || canonical_json({ header, recipients })
```

`header` includes the format version, the content/key-wrap/fingerprint algorithm identifiers, the file name, the date and the random `id_archivo`. `recipients` includes every entry (`id`, `key_id`, `encrypted_key`) **in order**. The JSON is canonical (sorted keys, no whitespace), so the AAD is deterministic.

### Module layout

| Module | Responsibility |
|:---|:---|
| `vault/public_key.py` | RSA key pairs, fingerprints, PEM import/export, RSA-OAEP wrap/unwrap |
| `vault/shared_container.py` | v2 format, strict validation, AAD construction, read/write |
| `vault/sharing.py` | High-level API: `cifrar_para_destinatarios`, `descifrar_como_destinatario` |

---

## 3. Security Decisions

### How do recipients identify their key?

Each entry carries a `key_id`: the **SHA-256 of the DER SubjectPublicKeyInfo** encoding of the recipient's public key (full 256 bits, hex, not truncated).

- **Deterministic:** the same public key always gives the same ID; different keys give different IDs (SHA-256 collision resistance).
- **Derived, not declared:** when opening a file, the recipient's `key_id` is computed from the private key they present. The lookup never trusts a name typed by the user.
- **No confusion:** the container is rejected if two entries share an `id` or a `key_id`, so a lookup has at most one match.
- **Optional identity check:** if the caller passes `id_usuario`, the entry found must carry that `id`. Presenting Bob's key as "alice" fails.
- **Identity is bound cryptographically:** the RSA-OAEP *label* of every wrapped key is `{file id, key_id, recipient id}`. Moving an entry to another container, or renaming its `id`, makes unwrapping fail.

### What happens if an attacker modifies the recipient list?

The whole list (with order, IDs, key IDs and wrapped keys) is part of the AAD of AES-GCM, so any change makes the authentication tag fail for **every** recipient, including recipients whose own entry was not touched. This holds against anyone who does not hold the file key (outsiders and non-recipients). A recipient does hold the file key, so see the limitations below.

| Attack | Result |
|:---|:---|
| Add a recipient entry | `InvalidTag` |
| Remove a recipient entry | The removed user has no entry (`DestinatarioNoAutorizado`); everyone else gets `InvalidTag` |
| Reorder entries | `InvalidTag` |
| Change an `id` or `key_id` | `InvalidTag` (or `ErrorDeAcceso` for the affected user, via the OAEP label) |
| Modify or swap an `encrypted_key` | `InvalidTag` / `ErrorDeAcceso` |
| Copy an entry from another container | `ErrorDeAcceso` (OAEP label includes the file ID) |
| Change an algorithm identifier or version | `ContenedorInvalido` (strict validation); also part of the AAD (tested separately) |
| Add unknown fields or duplicate JSON keys | `ContenedorInvalido` (strict parser) |
| Re-encode Base64 non-canonically | `ContenedorInvalido` (only canonical Base64 is accepted) |
| Look-alike recipient IDs (case, NFC/NFD, zero-width or bidi characters) | Rejected when encrypting and when validating a container |

Note that OAEP wrapping happens *before* the AAD is computed, and the AAD includes the wrapped keys. This is not circular: the OAEP label depends only on the file ID, the key ID and the recipient ID.

### What happens if the public key is wrong?

- **A wrong key that is not the intended person's** (for example, Mallory's key registered under "bob"): the system cannot know it is wrong. The file is wrapped for whoever owns that key, so the wrong person gets access and the intended recipient does not.
- **Mitigation implemented:** `verificar_huella()` compares a public key to a fingerprint obtained through a trusted channel (in person, a signed directory, etc.). Share only after the check passes.
- **A weak or unsupported key** is rejected before use: non-RSA keys and RSA keys under 2048 bits raise `ValueError`. The default is 3072 bits.
- **A recipient using a different private key** (for example after regenerating their key pair) has a different `key_id` and finds no entry.

A real deployment needs a trustworthy source of public keys (PKI, a verified key directory, or fingerprint pinning). This project provides the fingerprint check but not the directory.

---

## 4. Known Limitations

- **The origin of a container is not authenticated.** Public keys are public, so any outsider can build a brand-new, fully valid container with content and recipients of their choosing. D3 gives confidentiality against non-recipients and detects modification of an *existing* container by anyone who does not hold the file key. It does not prove who created it. Digital signatures would address this.
- **Recipients are trusted with the file key.** A recipient can decrypt, can re-share the file key, and (because AES-GCM uses a shared key) can build a modified container with a valid tag. D3 does not authenticate recipients to each other.
- **No key commitment.** AES-GCM does not commit to its key. A malicious *sender* could wrap different file keys for different recipients so that each decrypts a different valid plaintext. "All recipients see the same plaintext" is guaranteed only for honest senders; sender signatures or an explicit key-commitment value would fix this.
- **Metadata is not confidential.** The recipient list, the `key_id` values (linkable across files for the same key) and the file name are stored in plaintext. They are authenticated, not hidden.
- **The file name is untrusted data.** It can contain path separators or unusual characters. `abrir_archivo_compartido` never uses it as a path; any caller that does must sanitize it first.
- **No revocation of past access.** Removing a recipient requires re-encrypting the file with a new file key and a new list. Anyone who already has the old file key and the old container can still read that copy.
- **Changing the recipient list means re-encrypting.** Because the list is authenticated, adding or removing a recipient produces a new container.
- **No public-key authenticity infrastructure** (see above).
- **RSA is not post-quantum secure.**
- **Private keys** are exported as password-encrypted PKCS#8 PEM. Storing and protecting them is the user's responsibility; `*.pem` and `*.key` are already ignored by Git.

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
| Public key encryption only for small keys | `test_no_se_pueden_envolver_datos_grandes`, `test_archivo_grande_no_pasa_por_rsa` |
| Wrong public key | `test_clave_publica_equivocada_da_acceso_a_la_persona_equivocada` |
| Strict container validation | `tests/test_shared_container.py` |
