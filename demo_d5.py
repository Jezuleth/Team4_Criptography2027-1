"""D5 demo: digital signatures (Ed25519) on top of the D3 shared container."""
import json
from pathlib import Path

from vault.public_key import DestinatarioNoAutorizado, generar_par_claves
from vault.signatures import ErrorFirma, generar_par_claves_firma, huella_clave_firma
from vault.signed_sharing import abrir_archivo_firmado, firmar_y_compartir_archivo

folder = Path("demo_d5_archivos")
folder.mkdir(exist_ok=True)
original = folder / "message.txt"
vault = folder / "message.vault"
message = b"Confidential document of Team 4 - UNAM"

print("\n=== D5 - DIGITAL SIGNATURES ===")

print("\n[1] Generating keys...")
alice, bob, mallory = generar_par_claves(), generar_par_claves(), generar_par_claves()
signer = generar_par_claves_firma()  # Ed25519, the sender's signing key
impostor = generar_par_claves_firma()
signer_pub = signer.public_key()
print(f"Signer fingerprint: {huella_clave_firma(signer_pub)}")

print("\n[2] Encrypting for Alice and Bob, then signing...")
original.write_bytes(message)
firmar_y_compartir_archivo(
    original, vault, {"alice": alice.public_key(), "bob": bob.public_key()}, signer
)
print("OK: signed message.vault created.")

print("\n[3] Authorized recipients verify the signature and decrypt...")
for name, key in [("alice", alice), ("bob", bob)]:
    data = abrir_archivo_firmado(vault, key, name, signer_pub)
    assert data == message
    print(f"OK: {name} verified the signature and recovered the file.")


def must_fail(label, exc, path, key, name, pub):
    try:
        abrir_archivo_firmado(path, key, name, pub)
    except exc:
        print(f"OK: {label}")
    else:
        raise AssertionError(f"ERROR: {label} was accepted.")


print("\n[4] Attacks...")
container = json.loads(vault.read_text(encoding="utf-8"))

tampered = dict(container)
c = tampered["ciphertext"]
tampered["ciphertext"] = ("A" if c[0] != "A" else "B") + c[1:]
(folder / "tampered.vault").write_text(json.dumps(tampered), encoding="utf-8")
must_fail("modified ciphertext rejected before decrypting.", ErrorFirma,
          folder / "tampered.vault", bob, "bob", signer_pub)

stripped = {k: v for k, v in container.items() if k != "signature"}
(folder / "stripped.vault").write_text(json.dumps(stripped), encoding="utf-8")
must_fail("container with the signature removed rejected.", ErrorFirma,
          folder / "stripped.vault", bob, "bob", signer_pub)

must_fail("signature from a different signer rejected.", ErrorFirma,
          vault, bob, "bob", impostor.public_key())

must_fail("Mallory (valid signature, not a recipient) rejected.",
          DestinatarioNoAutorizado, vault, mallory, "mallory", signer_pub)

print("\n=== D5 DEMO FINISHED ===")
