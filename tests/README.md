# Tests

Test files and utilities for the encrypted nodes package.

## Files

- `test_crypto.py` - Unit tests for the crypto module
- `encrypt_input_image.py` - CLI to encrypt images for input nodes
- `decrypt_output_image.py` - CLI to decrypt output images
- `test_image.png` - Sample image for testing

## Usage

```bash
# Run crypto tests
python3 tests/test_crypto.py

# Encrypt an image for EncryptedLoadImage node
python3 tests/encrypt_input_image.py /path/to/image.png --generate-keys

# Decrypt an output image
python3 tests/decrypt_output_image.py /path/to/encrypted.enc
```

## Key Files

Key files (`*.pem`) are generated during testing and should NOT be committed.
Add to `.gitignore`:
```
*.pem
encrypted_*.txt
```
