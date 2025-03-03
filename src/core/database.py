import sqlite3
from contextlib import contextmanager
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


class DatabaseError(Exception):
    pass


class DataBase:
    """Database manager for password storage.

    Handles all database operations including:
    - Password entry creation
    - Password updates
    - Password deletion
    - Password retrieval
    """

    def __init__(self, db_path):
        self.db = db_path
        self.logger = SecurityLogger()
        self.initialize_db()
        # Run health check immediately after initialization
        self.check_database_health()

    @contextmanager
    def connect(self):
        """Context manager for database connections.

        Yields:
            sqlite3.Cursor: Database cursor
        """
        with sqlite3.connect(self.db) as con:
            c = con.cursor()
            try:
                yield c
                con.commit()
            except Exception:
                con.rollback()
                raise
            finally:
                c.close()

    def initialize_db(self):
        with self.connect() as c:
            c.execute(
                f""" CREATE TABLE IF NOT EXISTS {DATABASE['TABLE_NAMES']['passwords']} (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            user_name TEXT NOT NULL,
                            pwd BLOB NOT NULL,  -- BLOB for encrypted data
                            category TEXT NOT NULL,
                            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Audit trail
                            last_modified TIMESTAMP
                                )"""
            )

            # New users table
            c.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {DATABASE['TABLE_NAMES']['users']} (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

    def check_database_health(self):
        """Comprehensive database health check."""
        self.initialize_db()
        try:
            # Structure check
            with self.connect() as c:
                c.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [table[0] for table in c.fetchall()]
                if not DatabaseValidator.validate_db_structure(tables):
                    self.logger.log_security_event(
                        "db_health", "Invalid database structure"
                    )
                    raise DatabaseError("Invalid database structure")

            # Access check
            if not DatabaseValidator.validate_db_access(DATABASE["PATH"]):
                self.logger.log_security_event("db_health", "Database not accessible")
                raise DatabaseError("Database not accessible")

            # Space check
            if not DatabaseValidator.validate_disk_space(DATABASE["PATH"]):
                self.logger.log_security_event("db_health", "Insufficient disk space")
                raise DatabaseError("Insufficient disk space")
            self.logger.log_security_event("db_health", "Database health check passed")
            return True

        except sqlite3.Error as e:
            self.logger.log_security_event("db_health_error", str(e))
            raise DatabaseError(ErrorHandler.handle_db_error(e))

    def add_user(self, user_name: str, password_hash: str):
        """Add new user to database.

        Args:
            username (str): Username
            password_hash (str): Hashed password
        """
        with self.connect() as c:
            try:
                c.execute(
                    f"INSERT INTO {DATABASE['TABLE_NAMES']['users']} (username, password_hash) VALUES (?, ?)",
                    (user_name, password_hash),
                )
            except sqlite3.IntegrityError:
                raise ValueError("Username already exists")

    def add_pwd(self, user_name: str, pwd: bytes, category: str):
        """Insert a new password entry into the database.

        Args:
            user_name (str): Username/account name
            pwd (bytes): Encrypted password
            category (str): Password category
        """
        try:
            with self.connect() as c:
                c.execute(
                    f"""
                INSERT INTO {DATABASE['TABLE_NAMES']['passwords']} 
                (user_name, pwd, category, last_modified) 
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                """,
                    (user_name, pwd, category),
                )
                self.logger.log_password_operation("store", user_name)
        except sqlite3.IntegrityError:
            self.logger.log_security_event(
                "db_error", f"Duplicate entry for {user_name}"
            )
            raise DatabaseError("Entry already exists")
        except Exception as e:
            self.logger.log_security_event("db_error", str(e))
            raise DatabaseError(ErrorHandler.handle_db_error(e))

    def edit_pwd(self, id: int, user_name: str, pwd: bytes, category: str):
        """Edit password entry in the database.

        Args:
            id (int): Entry ID to update
            user_name (str): Username/account name
            pwd (bytes): Encrypted password
            category (str): Password category
        """
        with self.connect() as c:
            c.execute(
                f"""
            UPDATE {DATABASE['TABLE_NAMES']['passwords']} SET user_name = ?, pwd = ?, 
            category = ?, last_modified = CURRENT_TIMESTAMP WHERE id =?
            """,
                (user_name, pwd, category, id),
            )

    def delete_pwd(self, id: int):
        """Delete single password entry."""
        try:
            with self.connect() as c:
                self.logger.log_password_operation("delete", f"ID: {id}")
                c.execute(
                    f"DELETE FROM {DATABASE['TABLE_NAMES']['passwords']} WHERE id = ?",
                    (id,),
                )
        except Exception as e:
            self.logger.log_security_event(
                "db_error", f"Delete failed for ID {id}: {str(e)}"
            )
            raise

    def delete_category(self, category: str):
        """Delete all passwords in a category."""
        with self.connect() as c:
            c.execute(
                f"DELETE FROM {DATABASE['TABLE_NAMES']['passwords']} WHERE category = ?",
                (category,),
            )

    def clear_all_passwords(self):
        """Clear all passwords but keep table structure."""
        try:
            with self.connect() as c:
                c.execute(f"DLETE FROM{DATABASE['TABLE_NAMES']['passwords']}")
                self.logger.log_security_event("db_operation", "All passwords cleared")
        except Exception as e:
            self.logger.log_security_event("db_error", f"Clear all failed: {str(e)}")
            raise

    def get_all_passwords(self):
        """Retrieve all password entries.

        Returns:
            List[Tuple]: List of password entries
        """
        with self.connect() as c:
            c.execute(
                f"SELECT * FROM {DATABASE['TABLE_NAMES']['passwords']}"
            )  # Note: 'passwords' not 'db'
            return c.fetchall()

    def get_by_category(self, category: str):
        """Retrieve passwords by category."""
        with self.connect() as c:
            c.execute(
                f"SELECT * FROM {DATABASE['TABLE_NAMES']['passwords']} WHERE category = ?",
                (category,),
            )
            return c.fetchall()

    def get_by_username(self, user_name: str):
        """Retrieve passwords by username."""
        with self.connect() as c:
            c.execute(
                f"SELECT * FROM {DATABASE['TABLE_NAMES']['passwords']} WHERE user_name = ?",
                (user_name,),
            )
            return c.fetchall()
