# ComfyUI Encrypted Nodes

Custom nodes for encrypted image generation workflows on untrusted GPU hosts.

## Features

- **EncryptedSaveImage** - Encrypts generated images with backend's public key
- **EncryptedLoadImage** - Decrypts input images using container's private key
- **Two encryption modes**:
  - **RSA-4096** - Large keys (~3KB), requires file mounting
  - **X25519** - Small keys (64 hex chars), fits in environment variables ✨

## Installation

Mount as a custom node in ComfyUI:

```bash
# Docker mount
-v /path/to/comfyui-encrypted-nodes:/opt/ComfyUI/custom_nodes/comfyui-encrypted-nodes
```

Or clone directly into ComfyUI:

```bash
cd /path/to/ComfyUI/custom_nodes
git clone https://github.com/igorls/comfyui-encrypted-nodes.git comfyui-encrypted-nodes
```

Install Python deps (inside the same environment/container that runs ComfyUI):

```bash
python3 -m pip install -r /path/to/ComfyUI/custom_nodes/comfyui-encrypted-nodes/requirements.txt
```

## Quickstart (X25519 recommended)

This is the typical flow:

1. Generate a **container keypair** (X25519).
2. Put the container **private** key in the ComfyUI container (`CONTAINER_PRIVATE_KEY`).
3. Give the container **public** key to your backend (to encrypt inputs).
4. Put the backend **public** key in the ComfyUI container (`BACKEND_PUBLIC_KEY`) or pass it into the node.

See [docs/KEYS.md](docs/KEYS.md) for a longer guide.

## Key Generation

### X25519 (Recommended for cloud deployment)

```python
"""Run this from the repo root (the same folder as crypto.py)."""

from crypto import generate_x25519_keypair

private_key, public_key = generate_x25519_keypair()
# private_key: 64 hex chars (fits in env var!)
# public_key: 64 hex chars
```

One-liner:

```bash
python3 -c "from crypto import generate_x25519_keypair; priv,pub=generate_x25519_keypair(); print('CONTAINER_PRIVATE_KEY='+priv); print('CONTAINER_PUBLIC_KEY='+pub)"
```

Store the private key on the ComfyUI side (example with docker-compose):

```yaml
services:
  comfyui:
    environment:
      # X25519 private key (64 hex chars)
      CONTAINER_PRIVATE_KEY: "<64-hex-chars>"

      # Backend key used to encrypt outputs. For X25519, this is also 64 hex chars.
      BACKEND_PUBLIC_KEY: "<backend-public-key>"
```

Notes:

- X25519 keys are **hex** (64 chars), not PEM.
- This repo auto-detects key type: if the key looks like 64 hex chars it uses X25519; if it contains `-----BEGIN` it uses RSA.

Example keys:
```
CONTAINER_PRIVATE_KEY=80b5e3a8dff621d1fd722980de404d15bbfac472277125f2db8cf57206c0675c
BACKEND_PUBLIC_KEY=aa21dcad2dbefdfc9b8e1c73ee178299bb11dd6f4329fe36b2959deb019d4e00
```

### RSA-4096 (Legacy, larger keys)

```python
"""Run this from the repo root (the same folder as crypto.py)."""

from crypto import generate_keypair

private_key, public_key = generate_keypair()
# Store private_key in CONTAINER_PRIVATE_KEY_FILE
```

For RSA, it’s usually easier to write keys to files and mount them:

```bash
python3 -c "from crypto import generate_keypair; priv,pub=generate_keypair(); open('container_private.pem','w').write(priv); open('container_public.pem','w').write(pub); print('Wrote container_private.pem + container_public.pem')"
```

Example container config:

```yaml
services:
  comfyui:
    environment:
      CONTAINER_PRIVATE_KEY_FILE: /run/secrets/container_private.pem
      BACKEND_PUBLIC_KEY: /run/secrets/backend_public.pem
    volumes:
      - ./secrets/container_private.pem:/run/secrets/container_private.pem:ro
      - ./secrets/backend_public.pem:/run/secrets/backend_public.pem:ro
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CONTAINER_PRIVATE_KEY` | Container's private key (PEM format, newlines as `\n`) |
| `CONTAINER_PRIVATE_KEY_FILE` | Path to file containing private key (alternative) |
| `BACKEND_PUBLIC_KEY` | Backend's public key for encrypting outputs (optional, can be passed per-workflow) |

Tip (PEM in env vars): if you set a PEM key inline, encode newlines as `\n`.

## Nodes

### EncryptedSaveImage

Encrypts generated images for secure transmission to backend.

**Inputs:**
- `images` - IMAGE tensor from VAE Decode
- `public_key_pem` - Backend's public key (PEM format)
- `filename_prefix` - Prefix for saved files
- `save_to_disk` - Whether to save .enc files (default: False)

**Returns:** Encrypted base64 in WebSocket results

You can either:

- Pass the backend public key directly into the node input, or
- Set `BACKEND_PUBLIC_KEY` for the container and leave the input empty.

### EncryptedLoadImage

Decrypts input images for img2img workflows.

**Inputs:**
- `encrypted_base64` - Base64-encoded encrypted image from backend

**Outputs:**
- `IMAGE` - Decrypted image tensor
- `MASK` - Alpha mask (if present)

## Backend Integration (minimal example)

Your backend needs to encrypt/decrypt blobs the same way. Easiest path is to vendor/copy `crypto.py` into the backend project (and install `cryptography`).

Encrypt an input image for the `EncryptedLoadImage` node:

```python
from crypto import encrypt_to_base64

with open("input.png", "rb") as f:
  image_bytes = f.read()

encrypted_b64 = encrypt_to_base64(image_bytes, container_public_key)
```

Decrypt a `.enc` blob produced by the `EncryptedSaveImage` node:

```python
from crypto import decrypt_image

with open("output.enc", "rb") as f:
  encrypted_blob = f.read()

image_bytes = decrypt_image(encrypted_blob, backend_private_key)
```

See [docs/INTEGRATION.md](docs/INTEGRATION.md) for a fuller walkthrough.

## Testing

Run the crypto test suite:

```bash
python3 tests/test_crypto.py
```

## Security Model

- **Input images**: Encrypted by backend with container's public key
- **Output images**: Encrypted by container with backend's public key
- **Prompts**: Plaintext (for debugging)
- **Temp files**: Never written unencrypted

> ⚠️ **Note**: This provides defense-in-depth against host snooping. A determined attacker with root access could still dump memory.

## License

MIT — see [LICENSE](LICENSE).
