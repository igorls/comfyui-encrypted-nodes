#!/usr/bin/env python3
"""
Test script for encrypted nodes crypto module.

Run from the comfyui-encrypted-nodes directory:
    python3 tests/test_crypto.py
"""

import sys
import os

# Add repo root (one directory above tests/) to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import (
    generate_keypair,
    encrypt_image,
    decrypt_image,
    encrypt_to_base64,
    decrypt_from_base64
)


def test_keypair_generation():
    """Test RSA keypair generation."""
    print("Testing keypair generation...")
    private_key, public_key = generate_keypair()
    
    assert "-----BEGIN PRIVATE KEY-----" in private_key
    assert "-----END PRIVATE KEY-----" in private_key
    assert "-----BEGIN PUBLIC KEY-----" in public_key
    assert "-----END PUBLIC KEY-----" in public_key
    
    print("✓ Keypair generation works")
    return private_key, public_key


def test_encryption_roundtrip(private_key: str, public_key: str):
    """Test encrypt/decrypt roundtrip."""
    print("Testing encryption roundtrip...")
    
    # Create test image data (fake PNG header + some data)
    test_data = b'\x89PNG\r\n\x1a\n' + os.urandom(1024)  # ~1KB
    
    # Encrypt with public key
    encrypted = encrypt_image(test_data, public_key)
    
    # Verify encrypted data is different
    assert encrypted != test_data
    assert len(encrypted) > len(test_data)  # Should be larger due to overhead
    
    # Decrypt with private key
    decrypted = decrypt_image(encrypted, private_key)
    
    # Verify roundtrip
    assert decrypted == test_data
    
    print("✓ Encryption roundtrip works")


def test_base64_roundtrip(private_key: str, public_key: str):
    """Test base64 encrypt/decrypt roundtrip."""
    print("Testing base64 roundtrip...")
    
    test_data = b'\x89PNG\r\n\x1a\n' + os.urandom(2048)  # ~2KB
    
    # Encrypt to base64
    encrypted_b64 = encrypt_to_base64(test_data, public_key)
    
    # Verify it's valid base64
    import base64
    base64.b64decode(encrypted_b64)  # Should not raise
    
    # Decrypt from base64
    decrypted = decrypt_from_base64(encrypted_b64, private_key)
    
    assert decrypted == test_data
    
    print("✓ Base64 roundtrip works")


def test_large_image(private_key: str, public_key: str):
    """Test with larger data (simulating real image)."""
    print("Testing large image (~1MB)...")
    
    # Simulate a 1MP image (~3MB uncompressed, ~1MB as PNG)
    test_data = b'\x89PNG\r\n\x1a\n' + os.urandom(1024 * 1024)
    
    encrypted = encrypt_image(test_data, public_key)
    decrypted = decrypt_image(encrypted, private_key)
    
    assert decrypted == test_data
    
    print(f"✓ Large image works (input: {len(test_data)} bytes, encrypted: {len(encrypted)} bytes)")


def test_two_keypairs():
    """Test the two-keypair scenario (container + backend)."""
    print("Testing two-keypair scenario...")
    
    # Generate container keypair
    container_private, container_public = generate_keypair()
    
    # Generate backend keypair
    backend_private, backend_public = generate_keypair()
    
    # Simulate input image flow: backend encrypts with container's public key
    input_image = b'\x89PNG\r\n\x1a\n' + b'INPUT_IMAGE_DATA' + os.urandom(256)
    encrypted_input = encrypt_image(input_image, container_public)
    
    # Container decrypts with its private key
    decrypted_input = decrypt_image(encrypted_input, container_private)
    assert decrypted_input == input_image
    
    # Simulate output image flow: container encrypts with backend's public key
    output_image = b'\x89PNG\r\n\x1a\n' + b'OUTPUT_IMAGE_DATA' + os.urandom(256)
    encrypted_output = encrypt_image(output_image, backend_public)
    
    # Backend decrypts with its private key
    decrypted_output = decrypt_image(encrypted_output, backend_private)
    assert decrypted_output == output_image
    
    # Verify cross-decryption fails (security check)
    try:
        decrypt_image(encrypted_input, backend_private)
        print("✗ Cross-decryption should have failed!")
        sys.exit(1)
    except Exception:
        pass  # Expected
    
    print("✓ Two-keypair scenario works (cross-decryption correctly fails)")


def main():
    print("=" * 50)
    print("ComfyUI Encrypted Nodes - Crypto Test Suite")
    print("=" * 50)
    print()
    
    private_key, public_key = test_keypair_generation()
    test_encryption_roundtrip(private_key, public_key)
    test_base64_roundtrip(private_key, public_key)
    test_large_image(private_key, public_key)
    test_two_keypairs()
    
    print()
    print("=" * 50)
    print("All tests passed! ✓")
    print("=" * 50)


if __name__ == "__main__":
    main()
