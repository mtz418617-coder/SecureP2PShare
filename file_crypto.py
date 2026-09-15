import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAGIC = b"NSC1"
MAGIC_RSA_AES = b"NSA2"


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def derive_key(password: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), b"nasus-file-salt", 200_000, dklen=32)


def encrypt_bytes(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(16)
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(plaintext):
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        keystream.extend(block)
        counter += 1
    ciphertext = xor_bytes(plaintext, bytes(keystream[: len(plaintext)]))
    mac = hmac.new(key, MAGIC + nonce + ciphertext, hashlib.sha256).digest()
    return MAGIC + nonce + ciphertext + mac


def decrypt_bytes(blob: bytes, key: bytes) -> bytes:
    if len(blob) < 4 + 16 + 32:
        raise ValueError("encrypted file is too short")
    if blob[:4] != MAGIC:
        raise ValueError("not a valid encrypted file (magic mismatch)")
    nonce = blob[4:20]
    mac = blob[-32:]
    ciphertext = blob[20:-32]
    expected = hmac.new(key, MAGIC + nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("wrong password or corrupted file (MAC mismatch)")
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(ciphertext):
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        keystream.extend(block)
        counter += 1
    return xor_bytes(ciphertext, bytes(keystream[: len(ciphertext)]))


def encrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    key = derive_key(password)
    plaintext = input_path.read_bytes()
    encrypted = encrypt_bytes(plaintext, key)
    output_path.write_bytes(encrypted)


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    key = derive_key(password)
    encrypted = input_path.read_bytes()
    plaintext = decrypt_bytes(encrypted, key)
    output_path.write_bytes(plaintext)


def generate_rsa_keypair(private_key_path: Path, public_key_path: Path, bits: int = 2048) -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_key_path.write_bytes(private_pem)
    public_key_path.write_bytes(public_pem)


def _load_public_key(path: Path):
    return serialization.load_pem_public_key(path.read_bytes())


def _load_private_key(path: Path):
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def encrypt_bytes_hybrid(plaintext: bytes, public_key_path: Path) -> bytes:
    public_key = _load_public_key(public_key_path)

    aes_key = os.urandom(32)  # AES-256
    nonce = os.urandom(12)  # GCM nonce
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    envelope = {
        "v": 2,
        "alg": "AES-256-GCM+RSA-OAEP-SHA256",
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "enc_key": base64.b64encode(encrypted_key).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return MAGIC_RSA_AES + b"\n" + json.dumps(envelope, separators=(",", ":")).encode("utf-8")


def decrypt_bytes_hybrid(blob: bytes, private_key_path: Path) -> bytes:
    if not blob.startswith(MAGIC_RSA_AES + b"\n"):
        raise ValueError("not RSA+AES encrypted format")
    text = blob[len(MAGIC_RSA_AES) + 1 :].decode("utf-8")
    envelope = json.loads(text)

    private_key = _load_private_key(private_key_path)
    nonce = base64.b64decode(envelope["nonce"])
    encrypted_key = base64.b64decode(envelope["enc_key"])
    ciphertext = base64.b64decode(envelope["ciphertext"])

    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    aesgcm = AESGCM(aes_key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_file_hybrid(input_path: Path, output_path: Path, public_key_path: Path) -> None:
    output_path.write_bytes(encrypt_bytes_hybrid(input_path.read_bytes(), public_key_path))


def decrypt_file_hybrid(input_path: Path, output_path: Path, private_key_path: Path) -> None:
    output_path.write_bytes(decrypt_bytes_hybrid(input_path.read_bytes(), private_key_path))


def main() -> None:
    parser = argparse.ArgumentParser(description="File cryptography (legacy password mode + RSA/AES hybrid mode).")
    sub = parser.add_subparsers(dest="mode", required=True)

    p_enc = sub.add_parser("encrypt", help="Encrypt a file")
    p_enc.add_argument("--in", dest="in_path", required=True, help="Input file path")
    p_enc.add_argument("--out", dest="out_path", required=True, help="Output encrypted file path")
    p_enc.add_argument("--password", required=True, help="Encryption password")

    p_dec = sub.add_parser("decrypt", help="Decrypt a file")
    p_dec.add_argument("--in", dest="in_path", required=True, help="Input encrypted file path")
    p_dec.add_argument("--out", dest="out_path", required=True, help="Output decrypted file path")
    p_dec.add_argument("--password", required=True, help="Encryption password")

    p_keygen = sub.add_parser("keygen", help="Generate RSA keypair for hybrid encryption")
    p_keygen.add_argument("--private-key", required=True, help="Output private key PEM path")
    p_keygen.add_argument("--public-key", required=True, help="Output public key PEM path")
    p_keygen.add_argument("--bits", type=int, default=2048, help="RSA key size (default: 2048)")

    p_enc_rsa = sub.add_parser("encrypt-rsa", help="Encrypt file with AES-256-GCM + RSA-OAEP key wrapping")
    p_enc_rsa.add_argument("--in", dest="in_path", required=True, help="Input file path")
    p_enc_rsa.add_argument("--out", dest="out_path", required=True, help="Output encrypted file path")
    p_enc_rsa.add_argument("--public-key", required=True, help="Recipient public key PEM path")

    p_dec_rsa = sub.add_parser("decrypt-rsa", help="Decrypt file encrypted by encrypt-rsa")
    p_dec_rsa.add_argument("--in", dest="in_path", required=True, help="Input encrypted file path")
    p_dec_rsa.add_argument("--out", dest="out_path", required=True, help="Output decrypted file path")
    p_dec_rsa.add_argument("--private-key", required=True, help="Recipient private key PEM path")

    args = parser.parse_args()
    if args.mode == "keygen":
        generate_rsa_keypair(Path(args.private_key).resolve(), Path(args.public_key).resolve(), bits=args.bits)
        print(f"[ok] keypair generated -> {args.private_key} | {args.public_key}")
        return

    in_path = Path(args.in_path).resolve()
    out_path = Path(args.out_path).resolve()
    if not in_path.exists() or not in_path.is_file():
        raise FileNotFoundError(in_path)

    if args.mode == "encrypt":
        encrypt_file(in_path, out_path, args.password)
        print(f"[ok] encrypted -> {out_path}")
    elif args.mode == "decrypt":
        decrypt_file(in_path, out_path, args.password)
        print(f"[ok] decrypted -> {out_path}")
    elif args.mode == "encrypt-rsa":
        encrypt_file_hybrid(in_path, out_path, Path(args.public_key).resolve())
        print(f"[ok] encrypted (AES-256+RSA) -> {out_path}")
    else:
        decrypt_file_hybrid(in_path, out_path, Path(args.private_key).resolve())
        print(f"[ok] decrypted (AES-256+RSA) -> {out_path}")


if __name__ == "__main__":
    main()
