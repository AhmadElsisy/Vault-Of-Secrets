from encryption import Encryptor


class TestEncryptor:
    def test_password_hash(self):
        # Test hashing creates different hashes for same password
        encryptor = Encryptor("master_password")
        hash1 = encryptor.password_hash("test_password")
        hash2 = encryptor.password_hash("test_password")
        assert hash1 != hash2  # Should be different due to salt

    def test_verify_master_password(self):
        # Test password verification
        encryptor = Encryptor("master_password")
        encryptor.password_hash("test_password")

        # Use master_password parameter name
        assert encryptor.verify_master_password("master_password") is True
        assert encryptor.verify_master_password("wrong_password") is False

    def test_password_encryption_decryption(self):
        # Test full encryption/decryption cycle
        encryptor = Encryptor("master_password")
        original = "secret_password"
        encrypted = encryptor.password_encryption(original)
        decrypted = encryptor.password_decryption(encrypted)
        assert decrypted == original
