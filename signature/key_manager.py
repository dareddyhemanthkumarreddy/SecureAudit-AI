"""
SecureAudit-AI — Key Manager
Generates and stores an RSA keypair used to sign data
before upload. The private key signs; the public key
lets the TPA (auditor) verify signatures without ever
needing the private key.
"""

import os
import sys

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import config


class KeyManager:
    """Handles RSA keypair generation, saving, and loading."""

    PRIVATE_KEY_PATH = os.path.join(config.KEYS_DIR, "private_key.pem")
    PUBLIC_KEY_PATH = os.path.join(config.KEYS_DIR, "public_key.pem")

    @staticmethod
    def generate_keys():
        """Generates a new RSA-2048 keypair and saves both keys to disk."""
        os.makedirs(config.KEYS_DIR, exist_ok=True)

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # Save private key
        with open(KeyManager.PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))

        # Save public key
        with open(KeyManager.PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

        return private_key, public_key

    @staticmethod
    def load_private_key():
        """Loads the private key from disk. Raises if it doesn't exist yet."""
        if not os.path.exists(KeyManager.PRIVATE_KEY_PATH):
            raise FileNotFoundError(
                "No private key found. Run KeyManager.generate_keys() first."
            )

        with open(KeyManager.PRIVATE_KEY_PATH, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    @staticmethod
    def load_public_key():
        """Loads the public key from disk. Raises if it doesn't exist yet."""
        if not os.path.exists(KeyManager.PUBLIC_KEY_PATH):
            raise FileNotFoundError(
                "No public key found. Run KeyManager.generate_keys() first."
            )

        with open(KeyManager.PUBLIC_KEY_PATH, "rb") as f:
            return serialization.load_pem_public_key(f.read())

    @staticmethod
    def keys_exist():
        """Checks if both keys already exist on disk."""
        return (
            os.path.exists(KeyManager.PRIVATE_KEY_PATH)
            and os.path.exists(KeyManager.PUBLIC_KEY_PATH)
        )


if __name__ == "__main__":
    if KeyManager.keys_exist():
        print("Keys already exist at:")
        print(f"  Private: {KeyManager.PRIVATE_KEY_PATH}")
        print(f"  Public:  {KeyManager.PUBLIC_KEY_PATH}")
    else:
        KeyManager.generate_keys()
        print("New RSA-2048 keypair generated:")
        print(f"  Private: {KeyManager.PRIVATE_KEY_PATH}")
        print(f"  Public:  {KeyManager.PUBLIC_KEY_PATH}")