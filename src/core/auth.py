import csv
from time import time
import secrets
import string
import os
import sys
from pathlib import Path

# Setup paths
config_path = Path(__file__).parent.parent.parent / "src" / "config"
utils_path = Path(__file__).parent.parent.parent / "src" / "utils"
sys.path.extend([str(config_path), str(utils_path)])  # Add both paths at once

# Now imports after paths are set
from constants import SESSION_STATES, SECURITY, FILES, DATABASE
from validator import *
from logger import SecurityLogger
from database import DataBase
from encryption import Encryptor


class Authenticator:
    """
    A class to handle authentication.
    - Session management:
                          Create session
                          End seesion after 5 minutes, if the user asks for extension he got another 1 minute
    - Log in process:
                      Validate credentials
                      Create log in

    - Save session and terminates the file after ending.
      If the deletion failed, the file will be locked, and in any situation, the session file will be scrambled after ending.
    """

    def __init__(self):
        self.logger = SecurityLogger()
        self.db = DataBase(DATABASE["PATH"])
        self.encryptor = Encryptor

    def create_session(self, user_name):
        # Set session times
        self.session_start = time()
        self.session_end = SECURITY["SESSION_DURATION"]  # The span of session
        self.warning_time = (
            SECURITY["SESSION_DURATION"] - SECURITY["WARNING_TIME"]
        )  # A 1 minute warning before ending

        # Track session state
        self.SESSION_ACTIVE = SESSION_STATES["ACTIVE"]
        self.SESSION_WARNING = SESSION_STATES["WARNING"]
        self.SESSION_EXTENDED = SESSION_STATES["EXTENDED"]

        # Write the session details in csv file
        with open(FILES["SESSION_FILE"], "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(
                [
                    user_name,  # actual values, not column names
                    self.session_start,
                    self.session_end,
                    self.SESSION_ACTIVE,  # initial state
                ]
            )

    def check_session(self):
        # Check if the session already created
        try:
            with open(FILES["SESSION_FILE"], "r", newline="") as csvfile:
                reader = csv.reader(csvfile)
                session_data = next(reader)  # Get all fields
                # Can check for completeness/corruption
                if len(session_data) != 4:  # Expected fields
                    return None
                return session_data
        except Exception:
            return None

    def handle_authentication_error(self, error: Exception) -> str:
        """Handle authentication errors using ErrorHandler.

        Args:
            error: Caught exception

        Returns:
            str: Formatted error message
        """
        return ErrorHandler.handle_auth_error(error)

    def authenticate(self, user_name, password):
        stored_password = self.db.get_by_username(user_name)
        try:
            if stored_password:
                if self.encryptor.verify_master_password(stored_password[0], password):
                    self.create_session(user_name)
                    self.logger.log_auth_event(user_name, "login", True)
                    return True
                self.logger.log_auth_event(user_name, "login", False)
                return False

            # No stored password found
            self.logger.log_auth_event(user_name, "login", False)
            return self.handle_authentication_error(Exception("Invalid credentials"))

        except Exception as e:
            self.logger.log_security_event("auth_error", str(e))
            return self.handle_authentication_error(e)

    def register(self, user_name, password):
        if not InputValidator.validate_username(user_name):
            raise ValueError("Invalid username format.")

        try:

            encryptor = Encryptor(password)
            hashed_password = encryptor.password_hash(password)

            self.db.add_user(user_name, hashed_password)
            self.logger.log_auth_event(user_name, "register", True)
            return True  # Success case
        except FileExistsError:
            self.logger.log_auth_event(user_name, "register", False)
            return "Username already exists"
        except Exception as e:

            self.logger.log_security_event("registration_error", str(e))
            return f"Registration failed: {str(e)}"

    def check_session_status(self):
        """Check current session status."""
        session_data = self.check_session()
        if not session_data:
            return "no_session"

        user_name, session_start, session_end, session_state = session_data
        current_time = time()

        if current_time >= session_end:
            return SESSION_STATES["EXPIRED"]
        elif current_time >= self.warning_time:
            return SESSION_STATES["WARNING"]
        return SESSION_STATES["ACTIVE"]

    def extend_session(self):
        """Handle session extension."""
        session_data = self.check_session()
        if session_data:
            self.session_end += SECURITY["EXTENSION_TIME"]
            self.SESSION_EXTENDED = SESSION_STATES["EXTENDED"]
            # Update CSV with new session end time
            self.update_session_file(session_data)
            return True
        return False

    def end_session(self):
        """Handle session termination."""
        session_data = self.check_session()
        if not session_data:
            self.logger.log_security_event("session_end", "No active session")
            return "No active session found."

        user_name, _, session_end, _ = session_data
        try:
            # Session ending logic...
            self.scramble_session_file()
            self.logger.log_auth_event(user_name, "logout", True)
            return "Session ended successfully"
        except Exception as e:
            self.logger.log_security_event("session_end_error", str(e))
            return f"Session end failed: {str(e)}"

    def update_session_file(self, session_data):
        """Update session file with new data."""
        user_name, _, _, _ = session_data
        with open(FILES["SESSION_FILE"], "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(
                [
                    user_name,
                    session_data[1],  # Keep original start time
                    self.session_end,
                    self.SESSION_EXTENDED,
                ]
            )

    def scramble_session_file(self):
        """Scramble the session file content to secure the data after the session ends"""
        # Scrambling the file (writing random characters to each field)
        try:
            with open(FILES["SESSION_FILE"], "r+") as csvfile:
                content = csvfile.readlines()
                if content:
                    # Scramble each row of the session file
                    scrambled_content = []
                    for line in content:
                        scrambled_line = "".join(
                            secrets.choice(string.ascii_letters + string.digits)
                            for _ in line
                        )
                        scrambled_content.append(scrambled_line + "\n")

                    # Clear file and write scrambled content
                    csvfile.seek(0)
                    csvfile.truncate(0)
                    csvfile.writelines(scrambled_content)

        except Exception as e:
            print(f"Error scrambling session file: {str(e)}")

        try:
            os.remove(FILES["SESSION_FILE"])
        except OSError:
            pass  # File already scrambled anyway
