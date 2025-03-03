import logging
import os
import sys
from typing import Optional
import os
import sys
from pathlib import Path
config_path = Path(__file__).parent.parent.parent /"src"/ "config"
sys.path.append(str(config_path))
from constants import FILES


class Logger:
    def __init__(self, log_level = "INFO",
                  log_file= FILES["SECURITY_LOG"],
                  log_to_console = True):
        """
        Initialize the logger with specified configuration
        
        Args:
            log_level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            log_file: Optional file path for logging. If None, only console logging is used
            log_to_console: Whether to output logs to console
        """
       
          
        # Create logger instance
        self.logger = logging.getLogger("PortInspector")
        self.logger.setLevel(self.get_log_level(log_level))

        # Clear any existed handlers to prevent duplication
        self.logger.handlers.clear()

        # Set logging formatter
        console_formatter = logging.Formatter('[%(levelname)s] %(message)s')
        
        file_formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S')
        
        # Add logging to console if it requested
        if log_to_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)

        # Add file handler
        if log_file:
            # Creates logs directory
            log_dir = os.path.dirname(log_file)
            if log_dir and not os.path.exists(log_dir):
                try:
                    os.makedirs(log_dir)
                except OSError as e:
                    self.logger.error(f"Failed to create log directory: {e}")
                    log_to_console = True

            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)  

        # Convert logging level to logging constants
    def get_log_level(self, level: str) -> int:
        return getattr(logging, level.upper(), logging.INFO)

class SecurityLogger(Logger):
    """Logger specifically for password manager security events."""
    
    def __init__(self):
        super().__init__(
            log_level= "INFO",
            log_file= FILES["SECURITY_LOG"],
            log_to_console= True)
        
    def log_auth_event(self, username: str, event_type: str, success: bool):
        """Log authentication events.
        
        Args:
            username: User involved
            event_type: Type of event (login, register, etc.)
            success: Whether event succeeded
        """
        status = "SUCCESS" if success else "FAILED"
        self.logger.info(
            f"AUTH {status}: {event_type} attempt for user '{username}'"
        )
        
    def log_password_operation(self, operation: str, category: str):
        """Log password operations.
        
        Args:
            operation: Operation type (generate, update, delete)
            category: Password category
        """
        self.logger.info(
            f"PASSWORD: {operation} operation in category '{category}'"
        )
        
    def log_security_event(self, event_type: str, details: str):
        """Log general security events."""
        self.logger.warning(
            f"SECURITY: {event_type} - {details}"
        )