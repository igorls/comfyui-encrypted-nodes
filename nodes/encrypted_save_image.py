"""
EncryptedSaveImage node for ComfyUI.

Encrypts generated images with the backend's public key for secure transmission.
"""

import os
import io
import base64
from PIL import Image
import numpy as np

import folder_paths
from ..crypto import encrypt_to_base64, get_public_key_from_env


class EncryptedSaveImage:
    """
    Encrypts generated images using hybrid RSA+AES-GCM encryption.
    
    Primary delivery is via WebSocket (encrypted base64 in results).
    Optional disk saving as .enc files.
    """
    
    def __init__(self):
        self.output_dir = folder_paths.get_output_directory()
        self.type = "output"
        self.prefix_append = ""
        self.counter = 0
    
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "images": ("IMAGE",),
                "public_key_pem": ("STRING", {
                    "multiline": True,
                    "default": "",
                    "placeholder": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
                }),
                "filename_prefix": ("STRING", {"default": "encrypted"}),
            },
            "optional": {
                "save_to_disk": ("BOOLEAN", {"default": False}),
            }
        }
    
    RETURN_TYPES = ()
    FUNCTION = "save_encrypted"
    OUTPUT_NODE = True
    CATEGORY = "image/encrypted"
    
    def save_encrypted(self, images, public_key_pem: str, filename_prefix: str, save_to_disk: bool = False):
        """
        Encrypt and save/transmit images.
        
        Args:
            images: Batch of image tensors from VAE Decode
            public_key_pem: Backend's RSA public key (PEM format)
            filename_prefix: Prefix for saved files (if save_to_disk=True)
            save_to_disk: Whether to save .enc files to output directory
        
        Returns:
            UI dict with encrypted base64 data for WebSocket transmission
        """
        # Fall back to environment variable if no key provided
        if not public_key_pem.strip():
            public_key_pem = get_public_key_from_env()
            if not public_key_pem:
                raise ValueError(
                    "No public key provided. Pass public_key_pem input or set "
                    "BACKEND_PUBLIC_KEY environment variable."
                )
        
        results = []
        
        for idx, image in enumerate(images):
            # Convert tensor to PIL Image
            # Image tensor is [H, W, C] with values 0-1
            img_array = (image.cpu().numpy() * 255).astype(np.uint8)
            pil_image = Image.fromarray(img_array)
            
            # Convert to PNG bytes in memory
            buffer = io.BytesIO()
            # Strip metadata to prevent workflow leakage
            pil_image.info = {}
            pil_image.save(buffer, format='PNG', pnginfo=None)
            image_bytes = buffer.getvalue()
            
            # Encrypt the image
            encrypted_base64 = encrypt_to_base64(image_bytes, public_key_pem)
            
            # Save to disk if requested
            saved_path = None
            if save_to_disk:
                filename = f"{filename_prefix}_{self.counter:05d}.enc"
                filepath = os.path.join(self.output_dir, filename)
                
                encrypted_blob = base64.b64decode(encrypted_base64)
                with open(filepath, 'wb') as f:
                    f.write(encrypted_blob)
                
                saved_path = filepath
                self.counter += 1
            
            # Add to results for WebSocket transmission
            results.append({
                "encrypted_base64": encrypted_base64,
                "index": idx,
                "saved_path": saved_path,
            })
        
        # Return UI dict - ComfyUI will include this in WebSocket response
        return {"ui": {"encrypted_images": results}}


# Node registration
NODE_CLASS_MAPPINGS = {
    "EncryptedSaveImage": EncryptedSaveImage
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "EncryptedSaveImage": "Encrypted Save Image"
}
