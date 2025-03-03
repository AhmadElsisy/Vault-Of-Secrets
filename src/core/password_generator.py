import mmap
import secrets
import string
from contextlib import contextmanager
import sys
from pathlib import Path

config_path = Path(__file__).parent.parent.parent / "src" / "config"
sys.path.append(str(config_path))
from constants import SECURITY


# Creating the class
class PasswordGenerator:
    def __init__(self, min_length: int, n: int, size=1024):
        self.mem = mmap.mmap(-1, size, access=mmap.ACCESS_WRITE)
        self.min_length = SECURITY["MIN_LENGTH"]
        self.alphabet = string.ascii_letters + string.digits + string.punctuation
        self.n = (
            n
            if SECURITY["MIN_LENGTH"] <= n <= SECURITY["MAX_LENGTH"]
            else SECURITY["MIN_LENGTH"]
        )

    # Generate password function
    def generator(self) -> str:
        with self.secure_memory() as secure_mem:  # Using the context manager
            while True:
                password = "".join(secrets.choice(self.alphabet) for i in range(self.n))

                if (
                    any(c.islower() for c in password)
                    and any(c.isupper() for c in password)
                    and sum(c.isdigit() for c in password) >= 3
                    and any(c in string.punctuation for c in password)
                ):
                    # Handle memory usage for security
                    secure_mem.seek(0)
                    secure_mem.write(password.encode())
                    password_bytes = bytearray(password.encode("utf-8"))
                    password_bytes[:] = b"\0" * len(password_bytes)
                    return password

    @contextmanager
    def secure_memory(self):
        try:
            yield self.mem
        finally:
            self.mem.seek(0)
            self.mem.write(b"\0" * self.mem.size())

    # Delet memory
    def __del__(self):
        if hasattr(self, "mem"):
            self.mem.seek(0)
            self.mem.write(b"\0" * self.mem.size())
            self.mem.close()
