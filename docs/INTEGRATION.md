# Backend integration guide

This custom node encrypts/decrypts images using the functions in `crypto.py`.

## Minimal backend requirement

- Install `cryptography` (see `requirements.txt`).
- Vendor/copy `crypto.py` into your backend project.

## Encrypting an input image (backend → container)

The backend encrypts with the **container public key**. The resulting base64 is passed to the `EncryptedLoadImage` node input.

```python
from crypto import encrypt_to_base64

container_public_key = "<64-hex-x25519-public or PEM>"

with open("input.png", "rb") as f:
    image_bytes = f.read()

encrypted_b64 = encrypt_to_base64(image_bytes, container_public_key)
```

## Decrypting an output image (container → backend)

The backend decrypts with the **backend private key**.

```python
from crypto import decrypt_image

backend_private_key = "<64-hex-x25519-private or PEM>"

with open("output.enc", "rb") as f:
    encrypted_blob = f.read()

image_bytes = decrypt_image(encrypted_blob, backend_private_key)
with open("output.png", "wb") as f:
    f.write(image_bytes)
```

## Common pitfalls

- **Key type mismatch**: X25519-encrypted blobs require X25519 private keys (64-hex). RSA-encrypted blobs require PEM.
- **PEM env vars**: ensure newlines are passed correctly (use `\n` in env var, code converts it back).
- **Repo folder name**: the ComfyUI custom node folder uses hyphens; for scripts, run from the repo root so `import crypto` works.
