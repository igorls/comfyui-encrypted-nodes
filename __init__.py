"""
ComfyUI Encrypted Nodes

Custom nodes for encrypted image generation workflows on untrusted GPU hosts.

Provides:
- EncryptedSaveImage: Encrypts outputs with backend's public key
- EncryptedLoadImage: Decrypts inputs with container's private key
"""

from .nodes import NODE_CLASS_MAPPINGS, NODE_DISPLAY_NAME_MAPPINGS

# Required exports for ComfyUI custom node registration
__all__ = ['NODE_CLASS_MAPPINGS', 'NODE_DISPLAY_NAME_MAPPINGS']

# Package metadata
WEB_DIRECTORY = None  # No web extensions
