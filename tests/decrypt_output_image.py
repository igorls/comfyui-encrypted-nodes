#!/usr/bin/env python3
"""
Script to decrypt encrypted output images from EncryptedSaveImage node.

Usage:
    python decrypt_output_image.py <encrypted_file> [--private-key-file <key_file>] [--output <output_file>]
"""

import sys
import os
import argparse

# Add parent directory for crypto import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import decrypt_image


def main():
    parser = argparse.ArgumentParser(description='Decrypt an encrypted output image')
    parser.add_argument('encrypted_file', help='Path to the .enc file or base64 text file')
    parser.add_argument('--private-key-file', '-k', default='backend_private.pem',
                        help='Path to backend private key PEM file (default: backend_private.pem)')
    parser.add_argument('--output', '-o', help='Output image path (default: decrypted_<original>.png)')
    parser.add_argument('--base64', '-b', action='store_true',
                        help='Input file contains base64-encoded data instead of raw binary')
    
    args = parser.parse_args()
    
    # Check files exist
    if not os.path.exists(args.encrypted_file):
        print(f"Error: Encrypted file not found: {args.encrypted_file}", file=sys.stderr)
        sys.exit(1)
    
    if not os.path.exists(args.private_key_file):
        print(f"Error: Private key file not found: {args.private_key_file}", file=sys.stderr)
        sys.exit(1)
    
    # Load private key
    with open(args.private_key_file, 'r') as f:
        private_key = f.read()
    
    # Load encrypted data
    with open(args.encrypted_file, 'rb') as f:
        encrypted_data = f.read()
    
    # Handle base64 if needed
    if args.base64:
        import base64
        encrypted_data = base64.b64decode(encrypted_data)
    
    print(f"Decrypting {args.encrypted_file} ({len(encrypted_data)} bytes)...", file=sys.stderr)
    
    # Decrypt
    image_bytes = decrypt_image(encrypted_data, private_key)
    
    print(f"Decrypted size: {len(image_bytes)} bytes", file=sys.stderr)
    
    # Determine output path
    if args.output:
        output_path = args.output
    else:
        base_name = os.path.splitext(os.path.basename(args.encrypted_file))[0]
        output_path = f"decrypted_{base_name}.png"
    
    # Save decrypted image
    with open(output_path, 'wb') as f:
        f.write(image_bytes)
    
    print(f"Saved decrypted image to: {output_path}", file=sys.stderr)


if __name__ == '__main__':
    main()
