import pytest
from unittest.mock import MagicMock, patch
from password_manager import PasswordManager
from constants import SECURITY


class TestPasswordManager:
    @pytest.fixture
    def manager(self):
        # Setup with all mocked dependencies
        manager = PasswordManager.__new__(PasswordManager)
        manager.generator = MagicMock()
        manager.encryption = MagicMock()
        manager.db = MagicMock()
        manager.auth = MagicMock()
        manager.is_authenticated = True
        manager.logger = MagicMock()
        manager.auth.authenticate.return_value = True
        return manager

    def test_generate_new_password(self, manager):
        # Setup
        manager.generator.generator.return_value = "test_password"
        manager.encryption.password_encryption.return_value = b"encrypted"

        # Test
        result = manager.generate_new_password(16, "testuser", "social")

        # Verify flow including logging
        assert result == "test_password"  # Verify returned password
        manager.generator.generator.assert_called_once_with(16)
        manager.encryption.password_encryption.assert_called_once_with("test_password")
        manager.db.add_pwd.assert_called_once()
        manager.logger.log_password_operation.assert_called_once_with(
            "generate", "social"
        )

    def test_generate_password_db_failure(self, manager):
        """Test when password generates and encrypts but fails to store"""
        manager.generator.generator.return_value = "test_password"
        manager.encryption.password_encryption.return_value = b"encrypted"
        manager.db.add_pwd.side_effect = Exception("DB Error")

        with pytest.raises(Exception):
            manager.generate_new_password(16, "social")
            # Verify logging captured the error
            manager.logger.log_security_event.assert_called_once()

    def test_generate_password_encryption_failure(self, manager):
        # Test error handling when encryption fails
        manager.generator.generator.return_value = "test_password"
        manager.encryption.password_encryption.side_effect = Exception(
            "Encryption failed"
        )

        with pytest.raises(Exception):
            manager.generate_new_password(16, "social")

        # Verify DB store wasn't called after encryption failed
        manager.db.add_pwd.assert_not_called()

    def test_get_password_decryption_failure(self, manager):
        """Test handling of decryption failure when retrieving password"""
        manager.db.get_by_username.return_value = b"encrypted"
        manager.encryption.password_decryption.side_effect = Exception(
            "Decryption failed"
        )

        with pytest.raises(Exception):
            manager.get_by_user("testuser")
            manager.logger.log_security_event.assert_called_once()

    def test_delete_nonexistent_category(self, manager):
        """Test deleting category that doesn't exist"""
        manager.db.delete_category.side_effect = Exception("Category not found")

        with pytest.raises(Exception):
            manager.delete_category("nonexistent")
            manager.logger.log_security_event.assert_called_once()
