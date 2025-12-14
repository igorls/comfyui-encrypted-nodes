"""
Nodes subpackage for ComfyUI Encrypted Nodes.
"""

from .encrypted_save_image import EncryptedSaveImage, NODE_CLASS_MAPPINGS as SAVE_MAPPINGS, NODE_DISPLAY_NAME_MAPPINGS as SAVE_DISPLAY_MAPPINGS
from .encrypted_load_image import EncryptedLoadImage, NODE_CLASS_MAPPINGS as LOAD_MAPPINGS, NODE_DISPLAY_NAME_MAPPINGS as LOAD_DISPLAY_MAPPINGS

# Combine mappings
NODE_CLASS_MAPPINGS = {**SAVE_MAPPINGS, **LOAD_MAPPINGS}
NODE_DISPLAY_NAME_MAPPINGS = {**SAVE_DISPLAY_MAPPINGS, **LOAD_DISPLAY_MAPPINGS}

__all__ = [
    'EncryptedSaveImage',
    'EncryptedLoadImage',
    'NODE_CLASS_MAPPINGS',
    'NODE_DISPLAY_NAME_MAPPINGS',
]
