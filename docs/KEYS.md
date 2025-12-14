# Key generation & configuration

This project supports two key formats:

- **X25519** (recommended): 64 hex chars, easy to use in env vars.
- **RSA** (legacy): PEM files/strings.

The crypto layer auto-detects the key type:

- If the key is **64 hex chars** → X25519
- If it contains `-----BEGIN` → PEM/RSA

## Recommended setup (X25519)

You typically want *two* keypairs:

- **Container (ComfyUI) keypair**
  - Private key stays in the ComfyUI container (`CONTAINER_PRIVATE_KEY`).
  - Public key is shared to the backend (so it can encrypt inputs).

- **Backend keypair**
  - Private key stays on the backend.
  - Public key is shared to the container (so the container can encrypt outputs).

### Generate a container X25519 keypair

Run from the repo root (same folder as `crypto.py`):

```bash
python3 -c "from crypto import generate_x25519_keypair; priv,pub=generate_x25519_keypair(); print(priv); print(pub)"
```

### Configure ComfyUI container env vars

```bash
# Container private key (X25519)
export CONTAINER_PRIVATE_KEY="<64-hex-private>"

# Backend public key used for encrypting outputs (X25519)
export BACKEND_PUBLIC_KEY="<64-hex-backend-public>"
```

## RSA setup (PEM)

Generate RSA keys:

```bash
python3 -c "from crypto import generate_keypair; priv,pub=generate_keypair(); open('container_private.pem','w').write(priv); open('container_public.pem','w').write(pub); print('ok')"
```

Then mount the private key into the container and set:

- `CONTAINER_PRIVATE_KEY_FILE=/path/in/container/container_private.pem`

If you put PEM in an env var, represent newlines as `\n`.
