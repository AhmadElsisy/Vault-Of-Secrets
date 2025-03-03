from argon2 import PasswordHasher
import argon2
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
import os
import base64


class Encryptor:
    """Handles password encryption and master password authentication using Argon2."""

    def __init__(self, master_password):
        """Initialize encryptor with master password.

        Args:
            master_password (str): User's master password for authentication
        """
        self.master_password = master_password

        # Create hash for authentication
        self.master_password_hash = self.password_hash(master_password)

        # Generate encryption key
        self.encryption_key = self.generate_encryption_key()

    def password_hash(self, password):
        """Hash password using Argon2 for secure storage.

        Args:
            password (str): Password to hash

        Returns:
            str: Hashed password
        """

        ph = PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            encoding="utf-8",
            type=argon2.low_level.Type.ID,
        )
        return ph.hash(password)

    def verify_master_password(self, master_password):
        """Verify if provided password matches stored hash.

        Args:
            master_password (str): Password to verify

        Returns:
            bool: True if password matches, False otherwise
        """
        try:
            ph = PasswordHasher(
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                salt_len=16,
                encoding="utf-8",
                type=argon2.low_level.Type.ID,
            )
            return ph.verify(self.master_password_hash, master_password)
        except:
            return False

    def generate_encryption_key(self) -> Fernet:
        """Generate encryption key using Argon2id KDF.

        Returns:
            Fernet: Encryption key for password encryption/decryption
        """
        salt = os.urandom(16)
        # derive
        kdf = Argon2id(
            salt=salt,
            length=32,
            iterations=1,
            lanes=4,
            memory_cost=64 * 1024,
            ad=None,
            secret=None,
        )
        key = kdf.derive(self.master_password.encode())
        key = base64.urlsafe_b64encode(key)

        return Fernet(key)

    def password_encryption(self, password):
        """Encrypt a password using Fernet symmetric encryption.

        Args:
            password (str): Password to encrypt

        Returns:
            bytes: Encrypted password
        """
        return self.encryption_key.encrypt(password.encode())

    def password_decryption(self, encrypted):
        """Decrypt an encrypted password.

        Args:
            encrypted (bytes): Encrypted password to decrypt

        Returns:
            str: Decrypted password

        Raises:
            ValueError: If decryption fails
        """
        try:
            return self.encryption_key.decrypt(encrypted).decode()
        except Exception as e:
            # Handle decryption errors
            raise ValueError(f"Decryption failed: {str(e)}")
