"""
EncryptedLoadImage node for ComfyUI.

Decrypts encrypted input images using the container's private key.
"""

import io
import numpy as np
from PIL import Image
import torch

from ..crypto import decrypt_from_base64, get_private_key_from_env


class EncryptedLoadImage:
    """
    Decrypts encrypted input images for img2img workflows.
    
    Uses the container's private key (from environment) to decrypt
    images that were encrypted by the backend with the container's public key.
    """
    
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "encrypted_base64": ("STRING", {
                    "multiline": True,
                    "default": "",
                    "placeholder": "Base64-encoded encrypted image data"
                }),
            },
        }
    
    RETURN_TYPES = ("IMAGE", "MASK")
    RETURN_NAMES = ("image", "mask")
    FUNCTION = "load_encrypted"
    CATEGORY = "image/encrypted"
    
    def load_encrypted(self, encrypted_base64: str):
        """
        Decrypt and load an encrypted image.
        
        Args:
            encrypted_base64: Base64-encoded encrypted image from backend
        
        Returns:
            Tuple of (IMAGE tensor, MASK tensor)
        """
        if not encrypted_base64.strip():
            raise ValueError("No encrypted image data provided")
        
        # Get container's private key from environment
        private_key_pem = get_private_key_from_env()
        
        # Decrypt the image
        image_bytes = decrypt_from_base64(encrypted_base64, private_key_pem)
        
        # Load as PIL Image
        buffer = io.BytesIO(image_bytes)
        pil_image = Image.open(buffer)
        
        # Handle different image modes
        if pil_image.mode == 'RGBA':
            # Extract alpha channel as mask
            rgba_array = np.array(pil_image).astype(np.float32) / 255.0
            rgb_array = rgba_array[:, :, :3]
            alpha_array = rgba_array[:, :, 3]
            
            # Create mask (inverted alpha - 1 where transparent)
            mask = 1.0 - alpha_array
        elif pil_image.mode == 'LA' or pil_image.mode == 'L':
            # Grayscale with optional alpha
            pil_image = pil_image.convert('RGBA')
            rgba_array = np.array(pil_image).astype(np.float32) / 255.0
            rgb_array = rgba_array[:, :, :3]
            alpha_array = rgba_array[:, :, 3]
            mask = 1.0 - alpha_array
        else:
            # RGB or other modes without alpha
            pil_image = pil_image.convert('RGB')
            rgb_array = np.array(pil_image).astype(np.float32) / 255.0
            # Empty mask (all zeros = fully opaque)
            mask = np.zeros((pil_image.height, pil_image.width), dtype=np.float32)
        
        # Convert to tensors
        # ComfyUI expects [B, H, W, C] for images
        image_tensor = torch.from_numpy(rgb_array).unsqueeze(0)
        mask_tensor = torch.from_numpy(mask).unsqueeze(0)
        
        return (image_tensor, mask_tensor)


# Node registration
NODE_CLASS_MAPPINGS = {
    "EncryptedLoadImage": EncryptedLoadImage
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "EncryptedLoadImage": "Encrypted Load Image"
}
