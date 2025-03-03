from password_generator import PasswordGenerator
from auth import Authenticator
from database import DataBase
from encryption import Encryptor
import os
import sys
from pathlib import Path

# Setup paths
config_path = Path(__file__).parent.parent.parent / "src" / "config"
utils_path = Path(__file__).parent.parent.parent / "src" / "utils"
sys.path.extend([str(config_path), str(utils_path)])

from constants import DATABASE
from validator import *
from logger import SecurityLogger


class AuthenticationError(Exception):
    pass


class DataBaseError(Exception):
    pass


class RegistrationError(Exception):
    pass


class PasswordManager:
    """The main class to harmonize the work of generator,
    encryption, authentication, and database modules"""

    def __init__(self):
        self.logger = SecurityLogger()
        self.generator = PasswordGenerator(
            min_length=SECURITY["MIN_LENGTH"], n=SECURITY["MIN_LENGTH"]
        )
        self.auth = Authenticator
        self.db = DataBase(DATABASE["PATH"])
        self.encryption = Encryptor
        self.is_authenticated = False

    def register_user(self, user_name, password):
        """Register a new user."""
        try:
            # Hash the password
            encryptor = Encryptor(password)
            hashed_password = encryptor.password_hash(password)
            # Store in database
            self.db.add_user(user_name, hashed_password)
            return True
        except Exception as e:
            raise RegistrationError(f"Registration failed: {str(e)}")

    # Check the validation of the credentials
    def start_session(self, user_name, password):
        if not self.auth.authenticate(user_name, password):
            raise AuthenticationError("Invalid credentials.")
        self.is_authenticated = True
        # Existing authentication logic
        if self.auth.authenticate(user_name, password):
            self.auth.create_session(user_name)
            return user_name  # This becomes our current user
        raise AuthenticationError("Invalid credentials")

    def get_current_user(self):
        """Get current authenticated user from session."""
        session_data = self.auth.check_session()
        if session_data:
            return session_data[0]  # Username is first element
        return None

    def extend_session(self):
        """Extend current session by 1 minute."""
        return self.auth.extend_session  # Use auth's extension

    def get_session_end(self):
        """Get current session end time."""
        return self.auth.session_end  # Get from auth

    def end_session(self):
        """End the current session."""
        return self.auth.end_session()  # Use auth's end session

    # Layered security for double-checking authentication
    def check_auth(self):
        if not self.is_authenticated:
            raise AuthenticationError("Not Authenticated.")

        # chaeck session validity
        if not self.auth.check_session():
            self.is_authenticated = False
            raise AuthenticationError("Session Expired.")

    # Generate password, encrypt, and store
    def generate_new_password(self, length, user_name, category):
        if not InputValidator.validate_category(category):
            raise ValueError("Invalid category format.")
        # Double-check session validity
        if not self.auth.check_session():
            raise AuthenticationError("Session expired or invalid")

        # check user authentication
        self.check_auth()

        try:
            # Generate new password
            new_password = self.generator.generator(length)

            # Encrypt the new password
            encrypted_pwd = self.encryption.password_encryption(new_password)

            # Store the encrypted password
            self.db.add_pwd(user_name, encrypted_pwd, category)
            self.logger.log_password_operation("generate", category)
            return new_password

        except Exception as e:
            self.logger.log_security_event("generation_error", str(e))
            raise

    # Update an existing password
    def update_password(self, user_name, category, length, id):
        # check user authentication
        self.check_auth()

        # Generate new password
        updated_password = self.generator.generator(length)

        # Encrypt the new password
        encrypted_pwd = self.encryption.password_encryption(updated_password)

        # Store the encrypted password
        try:
            self.db.edit_pwd(user_name, encrypted_pwd, category, id)
        except Exception as e:
            raise DataBaseError(f"Update failed: {str(e)}")

        return updated_password

    def get_by_user(self, user_name):
        # check user authentication
        self.check_auth()

        try:
            encrypted_pwd = self.db.get_by_username(user_name)
            if not encrypted_pwd:
                raise DataBaseError(f"No password found for {user_name}")
            return self.encryption.password_decryption(encrypted_pwd)
        except Exception as e:
            raise DataBaseError(f"Fetching failed: {str(e)}")

    def get_by_category(self, category):
        # check user authentication
        self.check_auth()

        try:
            encrypted_passwords = self.db.get_by_category(category)
            if not encrypted_passwords:
                raise DataBaseError(f"No passwords found for {category}")

            # Decrypt each password in the list
            decrypted_passwords = [
                self.encryption.password_decryption(pwd) for pwd in encrypted_passwords
            ]
            return decrypted_passwords

        except Exception as e:
            raise DataBaseError(f"Fetching failed: {str(e)}")

    def get_all(self):
        # check user authentication
        self.check_auth()

        try:
            encrypted_passwords = self.db.get_all_passwords()
            if not encrypted_passwords:
                raise DataBaseError("No passwords found")

            # Decrypt each password
            decrypted_passwords = [
                self.encryption.password_decryption(pwd) for pwd in encrypted_passwords
            ]
            return decrypted_passwords

        except Exception as e:
            raise DataBaseError(f"Fetching failed: {str(e)}")

    def delete_password(self, id):
        # Single password deletion
        self.check_auth()

        try:
            self.db.delete_pwd(id)
            self.logger.log_password_operation("delete")
        except Exception as e:
            self.logger.log_security_event("deletion_error", str(e))
            raise DataBaseError(f"Deletion failed: {str(e)}")

    def delete_category(self, category):
        # Multiple passwords deletion
        self.check_auth()
        try:
            self.db.delete_category(category)
            self.logger.log_password_operation("delete_category", category)
        except Exception as e:
            self.logger.log_security_event("category_deletion_error", str(e))
            raise DataBaseError(f"Category deletion failed: {str(e)}")

    def clear_all(self):
        # Complete cleanup
        self.check_auth()
        try:
            self.db.clear_all_passwords()
            self.logger.log_security_event("clear_all", "All passwords cleared")
        except Exception as e:
            self.logger.log_security_event("clear_all_error", str(e))
            raise DataBaseError(f"Clear operation failed: {str(e)}")
