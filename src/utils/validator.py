import sys
from pathlib import Path
config_path = Path(__file__).parent.parent.parent /"src"/ "config"
sys.path.append(str(config_path))
from constants import SECURITY, DATABASE
import os
import platform


# src/utils/validators.py

class InputValidator:
    @staticmethod
    def validate_password_length(length: int) -> bool:
        """Validate password length against constants."""
        try:
            return SECURITY['MIN_LENGTH'] <= length <= SECURITY['MAX_LENGTH']
        except ValueError:
            return False

    @staticmethod
    def validate_username(username: str) -> bool:
        """Validate username format and length.
        
        Rules:
        - Must be string
        - Length between 3 and 12 characters
        - Only alphanumeric and underscores
        - Can't start with number
        """
        try:
             # Check the type
            if isinstance(username, str):
                return True
            
            # Check if empty
            if not username:
                return False
        
            # Check length
            if not (3 <= len(username) <= 12):
                return False
                
            # Check characters (alphanumeric and underscore only)
            if not username.replace('_', '').isalnum():
                return False
                
            # Can't start with number
            if username[0].isdigit():
                return False
            
            return True
            
        except Exception:
            return False    

    @staticmethod
    def validate_category(category: str) -> bool:
        """Validate category name.
        
        Rules:
        - Must be string
        - Not empty
        - Only letters, numbers, spaces, and underscores
        - Length between 2 and 20 characters
        """
        try:
            if not isinstance(category, str):
                return False
                
            if not category or category.isspace():
                return False
                
            if not (2 <= len(category) <= 20):
                return False
                
            # Allow letters, numbers, spaces, underscores
            if not all(c.isalnum() or c.isspace() or c == '_' for c in category):
                return False
                
            return True
            
        except Exception:
            return False

class ErrorHandler:
    @staticmethod
    def handle_auth_error(error: Exception) -> str:
        """Format and handle authentication errors.
        
        Args:
            error: The caught exception
            
        Returns:
            str: User-friendly error message
        """
        error_str = str(error).lower()
        
        # Authentication specific errors
        if "invalid credentials" in error_str:
            return "Invalid username or password"
        elif "no active session" in error_str:
            return "Session expired. Please login again"
        elif "username exists" in error_str:
            return "Username already taken. Please choose another"
        elif "password length" in error_str:
            return f"Password must be between {SECURITY['MIN_LENGTH']} and {SECURITY['MAX_LENGTH']} characters"
            
        # Generic auth errors
        return "Authentication failed. Please try again"

    @staticmethod
    def handle_session_error(error: Exception) -> str:
        """Handle session-related errors."""
        error_str = str(error).lower()
        
        if "expired" in error_str:
            return "Session has expired"
        elif "extension" in error_str:
            return "Could not extend session"
            
        return "Session error occurred"

    @staticmethod
    def handle_db_error(error: Exception) -> str:
        """Format and handle database errors.
        
        Args:
            error: The caught exception
            
        Returns:
            str: User-friendly error message
        """
        error_str = str(error).lower()
        
        # Connection errors
        if "unable to open database" in error_str:
            return "Could not connect to database"
        
        # Data errors
        elif "no such table" in error_str:
            return "Database structure error"
        elif "unique constraint" in error_str:
            return "Entry already exists"
        elif "foreign key constraint" in error_str:
            return "Related data missing"
            
        # Operation errors
        elif "readonly" in error_str:
            return "Database is locked or readonly"
        elif "disk full" in error_str:
            return "No space left for operation"
            
        # Data integrity
        elif "database is corrupted" in error_str:
            return "Database integrity error"
            
        # Generic fallback
        return "Database operation failed"
    
# In validators.py
class DatabaseValidator:
    @staticmethod
    def validate_db_structure(tables: list) -> bool:
        """Validate database has correct tables."""
        required_tables = DATABASE['TABLE_NAMES'].values()
        return all(table in tables for table in required_tables)

    @staticmethod
    def validate_db_access(db_path: str) -> bool:
        """Validate database is accessible and writable."""
        try:
            Path(db_path).touch()
            return True
        except (OSError, IOError):
            return False

    @staticmethod
    def validate_disk_space(db_path: str, min_space: int = 1024*1024) -> bool:
        """Validate sufficient disk space exists."""
        try:
            if platform.system() == 'Windows':
                # Windows specific
                import ctypes
                free_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    str(Path(db_path).parent), 
                    None, 
                    None, 
                    ctypes.byref(free_bytes)
                )
                free_space = free_bytes.value
            else:
                # Unix/Linux
                free_space = os.statvfs(Path(db_path).parent).f_bavail * \
                            os.statvfs(Path(db_path).parent).f_frsize
                
            return free_space >= min_space
        except Exception:
            # If we can't check space, assume it's okay
            return True