#!/usr/bin/env python3
"""
Script to encrypt an image for use with EncryptedLoadImage node.

Usage:
    python encrypt_input_image.py <image_path> [--public-key-file <key_file>]
    
If no key file is provided, a new keypair will be generated and saved.
"""

import sys
import os
import argparse

# Add parent directory for crypto import
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto import generate_keypair, encrypt_to_base64


def main():
    parser = argparse.ArgumentParser(description='Encrypt an image for EncryptedLoadImage node')
    parser.add_argument('image_path', help='Path to the image file to encrypt')
    parser.add_argument('--public-key-file', '-p', help='Path to public key PEM file')
    parser.add_argument('--generate-keys', '-g', action='store_true', 
                        help='Generate new keypair and save to container_private.pem / container_public.pem')
    parser.add_argument('--output', '-o', help='Output file for encrypted base64 (default: stdout)')
    
    args = parser.parse_args()
    
    # Check image exists
    if not os.path.exists(args.image_path):
        print(f"Error: Image file not found: {args.image_path}", file=sys.stderr)
        sys.exit(1)
    
    # Get or generate public key
    if args.generate_keys or (not args.public_key_file and not os.path.exists('container_public.pem')):
        print("Generating new keypair...", file=sys.stderr)
        private_key, public_key = generate_keypair()
        
        # Save keys
        with open('container_private.pem', 'w') as f:
            f.write(private_key)
        with open('container_public.pem', 'w') as f:
            f.write(public_key)
        
        print("Saved: container_private.pem (keep secret!)", file=sys.stderr)
        print("Saved: container_public.pem (share with backend)", file=sys.stderr)
    elif args.public_key_file:
        with open(args.public_key_file, 'r') as f:
            public_key = f.read()
    else:
        with open('container_public.pem', 'r') as f:
            public_key = f.read()
    
    # Read image
    with open(args.image_path, 'rb') as f:
        image_bytes = f.read()
    
    print(f"Encrypting {args.image_path} ({len(image_bytes)} bytes)...", file=sys.stderr)
    
    # Encrypt
    encrypted_base64 = encrypt_to_base64(image_bytes, public_key)
    
    print(f"Encrypted size: {len(encrypted_base64)} chars (base64)", file=sys.stderr)
    
    # Output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(encrypted_base64)
        print(f"Saved encrypted data to: {args.output}", file=sys.stderr)
    else:
        print("\n=== ENCRYPTED BASE64 (paste into EncryptedLoadImage node) ===\n")
        print(encrypted_base64)


if __name__ == '__main__':
    main()
