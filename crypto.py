"""
Cryptographic utilities for encrypted image workflows.

Supports two encryption modes:
- RSA-4096 + AES-256-GCM (large keys, ~3KB)
- X25519 + AES-256-GCM (small keys, 64 hex chars - env var friendly)

Key format detection is automatic based on key content.
"""

import os
import base64
from typing import Tuple, Union

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


# Constants
RSA_KEY_SIZE = 4096
AES_KEY_SIZE = 32  # 256 bits
NONCE_SIZE = 12    # 96 bits for GCM
X25519_KEY_SIZE = 32  # 256 bits

# Magic bytes for format detection
MAGIC_RSA = b'\x01'    # RSA-encrypted blob
MAGIC_X25519 = b'\x02' # X25519-encrypted blob


# =============================================================================
# RSA-4096 Functions (original)
# =============================================================================

def generate_keypair() -> Tuple[str, str]:
    """
    Generate a new RSA-4096 keypair.
    
    Returns:
        Tuple of (private_key_pem, public_key_pem) as strings
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
        backend=default_backend()
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem


# Alias for clarity
generate_rsa_keypair = generate_keypair


# =============================================================================
# X25519 Functions (new - small keys)
# =============================================================================

def generate_x25519_keypair() -> Tuple[str, str]:
    """
    Generate a new X25519 keypair.
    
    Returns:
        Tuple of (private_key_hex, public_key_hex) as hex strings (64 chars each)
        These are small enough to fit in environment variables!
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    # Export as raw bytes, convert to hex
    private_hex = private_key.private_bytes_raw().hex()
    public_hex = public_key.public_bytes_raw().hex()
    
    return private_hex, public_hex


def _x25519_encrypt(image_bytes: bytes, public_key_hex: str) -> bytes:
    """
    Encrypt using X25519 ECDH + AES-256-GCM.
    
    Args:
        image_bytes: Raw image data
        public_key_hex: Recipient's X25519 public key as hex string
        
    Returns:
        Encrypted blob with format:
        [1 byte: magic MAGIC_X25519]
        [32 bytes: ephemeral public key]
        [12 bytes: AES-GCM nonce]
        [N bytes: AES-GCM ciphertext + tag]
    """
    # Load recipient's public key
    recipient_public = x25519.X25519PublicKey.from_public_bytes(
        bytes.fromhex(public_key_hex)
    )
    
    # Generate ephemeral keypair for this encryption
    ephemeral_private = x25519.X25519PrivateKey.generate()
    ephemeral_public = ephemeral_private.public_key()
    
    # Perform ECDH
    shared_secret = ephemeral_private.exchange(recipient_public)
    
    # Derive AES key from shared secret using HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b'comfyui-encrypted-nodes',
        backend=default_backend()
    ).derive(shared_secret)
    
    # Encrypt with AES-GCM
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, image_bytes, None)
    
    # Pack: magic + ephemeral public key + nonce + ciphertext
    ephemeral_public_bytes = ephemeral_public.public_bytes_raw()
    encrypted_blob = MAGIC_X25519 + ephemeral_public_bytes + nonce + ciphertext
    
    return encrypted_blob


def _x25519_decrypt(encrypted_blob: bytes, private_key_hex: str) -> bytes:
    """
    Decrypt using X25519 ECDH + AES-256-GCM.
    
    Args:
        encrypted_blob: Encrypted data from _x25519_encrypt()
        private_key_hex: Recipient's X25519 private key as hex string
        
    Returns:
        Decrypted image bytes
    """
    # Load private key
    private_key = x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(private_key_hex)
    )
    
    # Unpack (skip magic byte)
    ephemeral_public_bytes = encrypted_blob[1:1 + X25519_KEY_SIZE]
    nonce = encrypted_blob[1 + X25519_KEY_SIZE:1 + X25519_KEY_SIZE + NONCE_SIZE]
    ciphertext = encrypted_blob[1 + X25519_KEY_SIZE + NONCE_SIZE:]
    
    # Reconstruct ephemeral public key
    ephemeral_public = x25519.X25519PublicKey.from_public_bytes(ephemeral_public_bytes)
    
    # Perform ECDH
    shared_secret = private_key.exchange(ephemeral_public)
    
    # Derive AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=b'comfyui-encrypted-nodes',
        backend=default_backend()
    ).derive(shared_secret)
    
    # Decrypt
    aesgcm = AESGCM(aes_key)
    image_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    
    return image_bytes


# =============================================================================
# RSA Functions (updated with magic byte)
# =============================================================================

def _rsa_encrypt(image_bytes: bytes, public_key_pem: str) -> bytes:
    """
    Encrypt using RSA-4096 + AES-256-GCM.
    """
    # Load public key
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode('utf-8'),
        backend=default_backend()
    )
    
    # Generate random AES key
    aes_key = os.urandom(AES_KEY_SIZE)
    
    # Encrypt AES key with RSA
    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Encrypt image data with AES-GCM
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, image_bytes, None)
    
    # Pack: magic + key_length + encrypted_key + nonce + ciphertext
    key_length = len(encrypted_aes_key).to_bytes(4, byteorder='big')
    encrypted_blob = MAGIC_RSA + key_length + encrypted_aes_key + nonce + ciphertext
    
    return encrypted_blob


def _rsa_decrypt(encrypted_blob: bytes, private_key_pem: str) -> bytes:
    """
    Decrypt using RSA-4096 + AES-256-GCM.
    """
    # Load private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None,
        backend=default_backend()
    )
    
    # Unpack (skip magic byte)
    key_length = int.from_bytes(encrypted_blob[1:5], byteorder='big')
    encrypted_aes_key = encrypted_blob[5:5 + key_length]
    nonce = encrypted_blob[5 + key_length:5 + key_length + NONCE_SIZE]
    ciphertext = encrypted_blob[5 + key_length + NONCE_SIZE:]
    
    # Decrypt AES key with RSA
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Decrypt image data with AES-GCM
    aesgcm = AESGCM(aes_key)
    image_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    
    return image_bytes


# =============================================================================
# Unified API (auto-detects key type)
# =============================================================================

def _is_x25519_key(key: str) -> bool:
    """Check if key is X25519 hex format (64 hex chars)."""
    key = key.strip()
    if len(key) == 64:
        try:
            bytes.fromhex(key)
            return True
        except ValueError:
            pass
    return False


def _is_pem_key(key: str) -> bool:
    """Check if key is PEM format."""
    return '-----BEGIN' in key


def encrypt_image(image_bytes: bytes, public_key: str) -> bytes:
    """
    Encrypt image data. Auto-detects key type (X25519 hex or RSA PEM).
    
    Args:
        image_bytes: Raw image data (e.g., PNG bytes)
        public_key: Recipient's public key (64-char hex for X25519, PEM for RSA)
    
    Returns:
        Encrypted blob (starts with magic byte for format detection)
    """
    if _is_x25519_key(public_key):
        return _x25519_encrypt(image_bytes, public_key.strip())
    elif _is_pem_key(public_key):
        return _rsa_encrypt(image_bytes, public_key)
    else:
        raise ValueError(
            "Invalid public key format. Expected 64-char hex (X25519) or PEM (RSA)."
        )


def decrypt_image(encrypted_blob: bytes, private_key: str) -> bytes:
    """
    Decrypt image data. Auto-detects format from magic byte.
    
    Args:
        encrypted_blob: Encrypted data from encrypt_image()
        private_key: Recipient's private key (64-char hex for X25519, PEM for RSA)
    
    Returns:
        Decrypted image bytes
    """
    if len(encrypted_blob) == 0:
        raise ValueError("Empty encrypted blob")
    
    magic = encrypted_blob[0:1]
    
    if magic == MAGIC_X25519:
        if not _is_x25519_key(private_key):
            raise ValueError("X25519-encrypted data requires X25519 private key (64-char hex)")
        return _x25519_decrypt(encrypted_blob, private_key.strip())
    elif magic == MAGIC_RSA:
        if not _is_pem_key(private_key):
            raise ValueError("RSA-encrypted data requires RSA private key (PEM format)")
        return _rsa_decrypt(encrypted_blob, private_key)
    else:
        # Legacy format (no magic byte) - assume RSA
        # Prepend magic byte and try again
        legacy_blob = MAGIC_RSA + encrypted_blob
        return _rsa_decrypt(legacy_blob, private_key)


def encrypt_to_base64(image_bytes: bytes, public_key: str) -> str:
    """
    Encrypt image and return as base64 string.
    
    Convenience wrapper for encrypt_image().
    """
    encrypted_blob = encrypt_image(image_bytes, public_key)
    return base64.b64encode(encrypted_blob).decode('utf-8')


def decrypt_from_base64(encrypted_base64: str, private_key: str) -> bytes:
    """
    Decrypt base64-encoded encrypted image.
    
    Convenience wrapper for decrypt_image().
    """
    encrypted_blob = base64.b64decode(encrypted_base64)
    return decrypt_image(encrypted_blob, private_key)


def get_private_key_from_env() -> str:
    """
    Get container's private key from environment.
    
    Checks CONTAINER_PRIVATE_KEY first, then CONTAINER_PRIVATE_KEY_FILE.
    Supports both X25519 (64-char hex) and RSA (PEM) formats.
    
    Returns:
        Private key string (hex for X25519, PEM for RSA)
        
    Raises:
        ValueError: If no private key is configured
    """
    # Check inline env var first (works for both X25519 hex and small RSA)
    private_key = os.environ.get('CONTAINER_PRIVATE_KEY')
    if private_key:
        # Replace literal \n with actual newlines (for PEM format)
        return private_key.replace('\\n', '\n')
    
    # Check file path (mainly for large RSA keys)
    key_file = os.environ.get('CONTAINER_PRIVATE_KEY_FILE')
    if key_file and os.path.exists(key_file):
        with open(key_file, 'r') as f:
            return f.read().strip()
    
    raise ValueError(
        "No private key configured. Set CONTAINER_PRIVATE_KEY or "
        "CONTAINER_PRIVATE_KEY_FILE environment variable."
    )


def get_public_key_from_env() -> str:
    """
    Get backend's public key from environment (optional).
    
    Returns:
        Public key string or empty string if not set
    """
    public_key = os.environ.get('BACKEND_PUBLIC_KEY', '')
    if public_key:
        return public_key.replace('\\n', '\n')
    return public_key

