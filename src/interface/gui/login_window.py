import sys
from pathlib import Path

# Add the core directory to Python's path
core_path = Path(__file__).parent.parent.parent / "core"
sys.path.append(str(core_path))
import password_manager
from password_manager import AuthenticationError
from password_manager import RegistrationError
import customtkinter as ctk
from .styles import *


class LoginWindow:
    def __init__(self):
        self.window = ctk.CTk()
        self.window.geometry(WINDOW_GEOMETRY["login"])
        self.window.title(APP_TITLE)
        self.password_manager = password_manager

        # Create tab view
        self.tabview = ctk.CTkTabview(self.window)
        self.tabview.pack(pady=PADDING["large"])

        # Create the tabs
        self.login_tab = self.tabview.add("Login")
        self.register_tab = self.tabview.add("Register")

        self.login_widgets()
        self.register_widgets()

    # Create login widgets
    def login_widgets(self):
        # Create username entry box
        self.username_entry = ctk.CTkEntry(
            self.login_tab,
            placeholder_text="Enter your username",
            width=ENTRY_WIDTH,
            corner_radius=CORNER_RADIUS["entry"],
            font=FONTS["normal"],
        )
        self.username_entry.pack(pady=PADDING["medium"])

        # Create password entry box
        self.password_entry = ctk.CTkEntry(
            self.login_tab,
            placeholder_text="Enter your password",
            width=ENTRY_WIDTH,
            corner_radius=CORNER_RADIUS["entry"],
            font=FONTS["normal"],
            show="*",
        )
        self.password_entry.pack(pady=PADDING["medium"])

        # Create a button
        self.login_button = ctk.CTkButton(
            self.login_tab,
            text="Login",
            width=BUTTON_WIDTH,
            corner_radius=CORNER_RADIUS["button"],
            font=FONTS["normal"],
            command=self.handle_login,
        )
        self.login_button.pack(pady=PADDING["small"])

    # Create register widgets
    def register_widgets(self):
        # Create username entry box
        self.reg_username_entry = ctk.CTkEntry(
            self.register_tab,
            placeholder_text="Enter your username",
            width=ENTRY_WIDTH,
            corner_radius=CORNER_RADIUS["entry"],
            font=FONTS["normal"],
        )
        self.reg_username_entry.pack(pady=PADDING["medium"])

        # Create password entry box
        self.reg_password_entry = ctk.CTkEntry(
            self.register_tab,
            placeholder_text="Enter your password",
            width=ENTRY_WIDTH,
            corner_radius=CORNER_RADIUS["entry"],
            font=FONTS["normal"],
            show="*",
        )
        self.reg_password_entry.pack(pady=PADDING["medium"])

        # Create a button
        self.register_button = ctk.CTkButton(
            self.register_tab,
            text="Register",
            width=BUTTON_WIDTH,
            corner_radius=CORNER_RADIUS["button"],
            font=FONTS["normal"],
            command=self.handle_register,
        )
        self.register_button.pack(pady=PADDING["small"])

    def handle_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        try:
            self.password_manager = password_manager.PasswordManager(password)
            self.password_manager.start_session(username, password)
            self.window.withdraw()
            from main_window import MainWindow

            MainWindow(self)
        except AuthenticationError as e:
            self.log_show_error(str(e))

    def handle_register(self):
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()

        try:
            self.password_manager = password_manager.PasswordManager(password)
            self.password_manager.register_user(username, password)
            self.window.withdraw()
            from main_window import MainWindow

            MainWindow(self)
        except RegistrationError as e:
            self.reg_show_error(str(e))

    def log_show_error(self, message):
        # Create error label if not exists
        if not hasattr(self, "error_label"):
            self.error_label = ctk.CTkLabel(
                self.login_tab,
                text="",
                text_color=COLORS["dark"]["error"],
                font=FONTS["small"],
            )
        self.error_label.pack(pady=PADDING["small"])

        self.error_label.configure(text=message)

    def reg_show_error(self, message):
        # Create error label if not exists
        if not hasattr(self, "error_label"):
            self.error_label = ctk.CTkLabel(
                self.register_tab,
                text="",
                text_color=COLORS["dark"]["error"],
                font=FONTS["small"],
            )
            self.error_label.pack(pady=PADDING["small"])

        self.error_label.configure(text=message)
