"""
EncryptedLoadImageFromFile node for ComfyUI.

Decrypts encrypted input images from a file in the input folder.
Compatible with pre-upload workflow where backend encrypts and uploads
images before job execution.
"""

import os
import io
import numpy as np
from PIL import Image
import torch
import folder_paths

from ..crypto import decrypt_image, get_private_key_from_env


class EncryptedLoadImageFromFile:
    """
    Load and decrypt image from encrypted file uploaded to input folder.
    
    Uses the container's private key (from environment) to decrypt
    images that were encrypted by the backend with the container's public key.
    
    This node is designed for the pre-upload optimization flow where images
    are uploaded BEFORE job execution for reduced latency.
    """
    
    @classmethod
    def INPUT_TYPES(cls):
        # Use STRING type to accept any filename (compatible with attachImage pattern)
        return {
            "required": {
                "image": ("STRING", {"default": "encrypted_input.enc"}),
            },
        }
    
    RETURN_TYPES = ("IMAGE", "MASK")
    RETURN_NAMES = ("image", "mask")
    FUNCTION = "load_encrypted_file"
    CATEGORY = "image/encrypted"
    
    # Enable dynamic file list refresh
    @classmethod
    def IS_CHANGED(cls, image):
        # Force re-execution when file changes
        input_dir = folder_paths.get_input_directory()
        image_path = os.path.join(input_dir, image)
        if os.path.exists(image_path):
            return os.path.getmtime(image_path)
        return float("nan")
    
    @classmethod
    def VALIDATE_INPUTS(cls, image):
        # Skip validation for dynamically uploaded files
        # The file may not exist at graph validation time but will exist at execution time
        return True
    
    def load_encrypted_file(self, image: str):
        """
        Load and decrypt an encrypted image file.
        
        Args:
            image: Filename of encrypted image in ComfyUI input folder
        
        Returns:
            Tuple of (IMAGE tensor, MASK tensor)
        """
        # Resolve file path
        input_dir = folder_paths.get_input_directory()
        image_path = os.path.join(input_dir, image)
        
        if not os.path.exists(image_path):
            raise FileNotFoundError(f"Encrypted image not found: {image_path}")
        
        # Read encrypted file
        with open(image_path, 'rb') as f:
            encrypted_blob = f.read()
        
        if len(encrypted_blob) == 0:
            raise ValueError(f"Empty encrypted file: {image}")
        
        # Get container's private key from environment
        private_key = get_private_key_from_env()
        
        # Decrypt the image
        image_bytes = decrypt_image(encrypted_blob, private_key)
        
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
    "EncryptedLoadImageFromFile": EncryptedLoadImageFromFile
}

NODE_DISPLAY_NAME_MAPPINGS = {
    "EncryptedLoadImageFromFile": "Encrypted Load Image (File)"
}
