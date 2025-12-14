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

## Key Generation

### X25519 (Recommended for cloud deployment)

```python
from comfyui_encrypted_nodes.crypto import generate_x25519_keypair

private_key, public_key = generate_x25519_keypair()
# private_key: 64 hex chars (fits in env var!)
# public_key: 64 hex chars
```

Example keys:
```
CONTAINER_PRIVATE_KEY=80b5e3a8dff621d1fd722980de404d15bbfac472277125f2db8cf57206c0675c
BACKEND_PUBLIC_KEY=aa21dcad2dbefdfc9b8e1c73ee178299bb11dd6f4329fe36b2959deb019d4e00
```

### RSA-4096 (Legacy, larger keys)

```python
from comfyui_encrypted_nodes.crypto import generate_keypair

private_key, public_key = generate_keypair()
# Store private_key in CONTAINER_PRIVATE_KEY_FILE
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CONTAINER_PRIVATE_KEY` | Container's private key (PEM format, newlines as `\n`) |
| `CONTAINER_PRIVATE_KEY_FILE` | Path to file containing private key (alternative) |
| `BACKEND_PUBLIC_KEY` | Backend's public key for encrypting outputs (optional, can be passed per-workflow) |

## Nodes

### EncryptedSaveImage

Encrypts generated images for secure transmission to backend.

**Inputs:**
- `images` - IMAGE tensor from VAE Decode
- `public_key_pem` - Backend's public key (PEM format)
- `filename_prefix` - Prefix for saved files
- `save_to_disk` - Whether to save .enc files (default: False)

**Returns:** Encrypted base64 in WebSocket results

### EncryptedLoadImage

Decrypts input images for img2img workflows.

**Inputs:**
- `encrypted_base64` - Base64-encoded encrypted image from backend

**Outputs:**
- `IMAGE` - Decrypted image tensor
- `MASK` - Alpha mask (if present)

## Security Model

- **Input images**: Encrypted by backend with container's public key
- **Output images**: Encrypted by container with backend's public key
- **Prompts**: Plaintext (for debugging)
- **Temp files**: Never written unencrypted

> ⚠️ **Note**: This provides defense-in-depth against host snooping. A determined attacker with root access could still dump memory.
