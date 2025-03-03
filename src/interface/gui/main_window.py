import customtkinter as ctk
import login_window
import os
import sys
from pathlib import Path

# Setup paths
config_path = Path(__file__).parent.parent.parent / "src" / "config"
core_path = Path(__file__).parent.parent.parent / "core"
utils_path = Path(__file__).parent.parent.parent / "src" / "utils"
sys.path.extend([str(config_path), str(utils_path), str(core_path)])

from password_manager import AuthenticationError
from .styles import *
from time import time
from constants import SECURITY
from validator import *


class MainWindow:
    def __init__(self):
        # Main window setup
        self.window = ctk.CTk()
        self.window.geometry(WINDOW_GEOMETRY["main"])
        self.window.title(APP_TITLE)

        # Keep reference to login window and get PasswordManager
        self.login_window = login_window.LoginWindow()
        self.password_manager = login_window.password_manager

        # Initialize empty categories list
        self.categories = []

        # Create tab view
        self.tabview = ctk.CTkTabview(self.window)
        self.tabview.pack(pady=PADDING["large"])

        # Create tabs
        self.generate_tab = self.tabview.add("Generate Password")
        self.view_tab = self.tabview.add("View Passwords")
        self.users_tab = self.tabview.add("User Management")

        # Create widgets for each tab
        self.create_generate_tab()
        self.create_view_tab()
        self.create_user_tab()
        # Start session timer immediately
        self.update_session_timer()

    def create_generate_tab(self):
        # Create password length entry box
        self.length_entry = ctk.CTkEntry(
            self.generate_tab,
            placeholder_text="Enter the length of password",
            width=ENTRY_WIDTH,
            corner_radius=CORNER_RADIUS["entry"],
            font=FONTS["normal"],
        )
        self.length_entry.pack(pady=PADDING["medium"])

        # Create category entry box
        self.categor_entry = ctk.CTkEntry(
            self.generate_tab,
            placeholder_text="Enter password category",
            width=ENTRY_WIDTH,
            corner_radius=CORNER_RADIUS["entry"],
            font=FONTS["normal"],
        )
        self.categor_entry.pack(pady=PADDING["medium"])

        # Create a generate button
        self.generate_button = ctk.CTkButton(
            self.generate_tab,
            text="Generate",
            width=BUTTON_WIDTH,
            corner_radius=CORNER_RADIUS["button"],
            font=FONTS["normal"],
            command=self.handle_generate,
        )
        self.generate_button.pack(pady=PADDING["small"])

    def update_category_view(self):
        """Update category dropdown with new categories."""
        try:
            # Update category filter values
            self.category_filter.configure(values=["All"] + self.categories)
            self.show_success(f"Category list updated")
        except Exception as e:
            self.show_error(f"Failed to update categories: {str(e)}")

    def handle_generate(self):
        try:
            # Validate category first
            category = self.categor_entry.get()
            if not InputValidator.validate_category(category):
                self.show_error("Invalid category name")
                return

            # Validate length
            try:
                length = int(self.length_entry.get())
                if not InputValidator.validate_password_length(length):
                    self.show_error(
                        f"Length must be between {SECURITY['MIN_LENGTH']} and {SECURITY['MAX_LENGTH']}"
                    )
                    return
            except ValueError:
                self.show_error("Please enter a valid number for length")
                return

            # Generate password
            password = self.login_window.password_manager.generate_new_password(
                length, category
            )

            # Show password and success
            self.show_generated_password(password)
            self.show_success("Password generated and saved!")

            # Update categories
            if category not in self.categories:
                self.categories.append(category)
                self.update_category_view()

        except AuthenticationError as e:
            self.show_error(ErrorHandler.handle_auth_error(e))
        except Exception as e:
            self.show_error(f"An error occurred: {str(e)}")

    def show_generated_password(self, password):
        if not hasattr(self, "password_label"):
            self.password_label = ctk.CTkLabel(
                self.generate_tab, text="", font=FONTS["normal"]
            )
            self.password_label.pack(pady=PADDING["medium"])
        self.password_label.configure(text=f"Generated Password: {password}")

    def show_error(self, message):
        if not hasattr(self, "error_label"):
            self.error_label = ctk.CTkLabel(
                self.generate_tab,
                text="",
                text_color=COLORS["dark"]["error"],
                font=FONTS["small"],
            )
            self.error_label.pack(pady=PADDING["small"])
        self.error_label.configure(text=message)

    def show_success(self, message):
        if not hasattr(self, "success_label"):
            self.success_label = ctk.CTkLabel(
                self.generate_tab,
                text="",
                text_color=COLORS["dark"]["fg"],
                font=FONTS["small"],
            )
            self.success_label.pack(pady=PADDING["small"])

        self.success_label.configure(text=message)

        # Clear success message after a few seconds
        self.window.after(3000, lambda: self.success_label.configure(text=""))

    def create_view_tab(self):
        # Search and Filter Frame (top section)
        search_frame = ctk.CTkFrame(self.view_tab)
        search_frame.pack(fill="x", padx=PADDING["medium"], pady=PADDING["medium"])

        # Search Entry
        self.search_entry = ctk.CTkEntry(
            search_frame,
            placeholder_text="Search passwords...",
            width=ENTRY_WIDTH,
            font=FONTS["normal"],
        )
        self.search_entry.pack(side="left", padx=PADDING["small"])

        # Category Filter Dropdown
        self.category_filter = ctk.CTkOptionMenu(
            search_frame,
            values=["All"] + self.categories,
            command=self.filter_by_category,
            width=BUTTON_WIDTH,
            font=FONTS["normal"],
        )
        self.category_filter.pack(side="right", padx=PADDING["small"])

        # Scrollable Frame for passwords
        self.password_frame = ctk.CTkScrollableFrame(
            self.view_tab, width=700, height=400  # Adjust based on main window size
        )
        self.password_frame.pack(fill="both", expand=True, padx=PADDING["medium"])

    def update_password_display(self):
        # Clear existing display first
        for widget in self.password_frame.winfo_children():
            widget.destroy()

        try:
            # Get passwords from password manager
            passwords = self.login_window.password_manager.get_all()

            for pwd in passwords:
                # Create frame for each password entry
                entry_frame = ctk.CTkFrame(self.password_frame)
                entry_frame.pack(fill="x", padx=PADDING["small"], pady=PADDING["small"])

                # Username/Category Label
                ctk.CTkLabel(
                    entry_frame, text=f"Category: {pwd.category}", font=FONTS["normal"]
                ).pack(side="left", padx=PADDING["small"])

                # Show/Hide Password Button
                show_btn = ctk.CTkButton(
                    entry_frame,
                    text="Show",
                    width=BUTTON_WIDTH // 2,
                    command=lambda p=pwd: self.toggle_password_visibility(p),
                )
                show_btn.pack(side="right", padx=PADDING["small"])
        except Exception as e:
            self.show_error(f"Failed to load passwords: {str(e)}")

    def toggle_password_visibility(self, password, button):
        current_text = button.cget("text")
        if current_text == "Show":
            button.configure(text="Hide")
            # Create or update password display label
            if not hasattr(self, "password_display_label"):
                self.password_display_label = ctk.CTkLabel(
                    button.winfo_parent(),  # Add to button's parent frame
                    text=password,
                    font=FONTS["normal"],
                )
                self.password_display_label.pack(side="left", padx=PADDING["small"])
        else:
            button.configure(text="Show")
            if hasattr(self, "password_display_label"):
                self.password_display_label.destroy()
                delattr(self, "password_display_label")

    def update_password(self, password):
        try:
            # Get new length from user
            dialog = ctk.CTkInputDialog(
                text="Enter new password length:", title="Update Password"
            )
            new_length = int(dialog.get_input())

            # Update password
            self.login_window.password_manager.update_password(
                password.id, password.category, new_length
            )

            # Refresh display
            self.update_password_display()
            self.show_success("Password updated successfully!")

        except ValueError:
            self.show_error("Please enter a valid length")
        except Exception as e:
            self.show_error(f"Failed to update password: {str(e)}")

    def show_delete_options(self, password=None):
        # Create a popup window for delete options
        delete_window = ctk.CTkToplevel(self.window)
        delete_window.title("Delete Options")
        delete_window.geometry("300x400")

        # Single Password Option
        if password:
            ctk.CTkButton(
                delete_window,
                text="Delete This Password",
                command=lambda: self.delete_password(password, delete_window),
            ).pack(pady=PADDING["medium"])

        # Delete by Category
        category_frame = ctk.CTkFrame(delete_window)
        category_frame.pack(pady=PADDING["medium"])

        category_dropdown = ctk.CTkOptionMenu(category_frame, values=self.categories)
        category_dropdown.pack(pady=PADDING["small"])

        ctk.CTkButton(
            category_frame,
            text="Delete Category",
            command=lambda: self.delete_category(
                category_dropdown.get(), delete_window
            ),
        ).pack()

        # Clear All Option
        ctk.CTkButton(
            delete_window,
            text="Clear All Passwords",
            command=lambda: self.clear_all_passwords(delete_window),
        ).pack(pady=PADDING["medium"])

    def delete_password(self, password, window=None):
        try:
            if self.confirm_deletion("password"):
                self.login_window.password_manager.delete_password(password.id)
                self.update_password_display()
                self.show_success("Password deleted successfully!")
                if window:
                    window.destroy()
        except Exception as e:
            self.show_error(f"Failed to delete password: {str(e)}")

    def delete_category(self, category, window=None):
        try:
            if self.confirm_deletion("category"):
                self.login_window.password_manager.delete_category(category)
                self.categories.remove(category)
                self.update_password_display()
                self.show_success(f"Category '{category}' deleted successfully!")
                if window:
                    window.destroy()
        except Exception as e:
            self.show_error(f"Failed to delete category: {str(e)}")

    def clear_all_passwords(self, window=None):
        try:
            if self.confirm_deletion("all passwords"):
                self.login_window.password_manager.clear_all()
                self.categories.clear()
                self.update_password_display()
                self.show_success("All passwords cleared successfully!")
                if window:
                    window.destroy()
        except Exception as e:
            self.show_error(f"Failed to clear passwords: {str(e)}")

    def confirm_deletion(self, item_type):
        dialog = ctk.CTkInputDialog(
            text=f"Type 'DELETE' to confirm deleting {item_type}:",
            title="Confirm Deletion",
        )
        return dialog.get_input() == "DELETE"

    def search_passwords(self, *args):  # *args to work with Entry binding
        search_term = self.search_entry.get().lower()
        try:
            # Get all passwords
            all_passwords = self.login_window.password_manager.get_all()

            # Simple search in categories
            filtered_passwords = [
                pwd for pwd in all_passwords if search_term in pwd.category.lower()
            ]

            # Update display with filtered results
            self.update_password_display(filtered_passwords)

        except Exception as e:
            self.show_error(f"Search failed: {str(e)}")

    def filter_by_category(self, category):
        try:
            if category == "All":
                # Show all passwords
                self.update_password_display()
            else:
                # Get passwords for selected category
                passwords = self.login_window.password_manager.get_by_category(category)
                self.update_password_display(passwords)

        except Exception as e:
            self.show_error(f"Filter failed: {str(e)}")

    def create_user_tab(self):
        # User Details Frame
        details_frame = ctk.CTkFrame(self.users_tab)
        details_frame.pack(fill="x", padx=PADDING["medium"], pady=PADDING["medium"])

        # Show current username
        ctk.CTkLabel(
            details_frame,
            text="Current User: Not logged in",  # Default text
            font=FONTS["normal"],
        ).pack(pady=PADDING["small"])

        # Session Information
        session_frame = ctk.CTkFrame(self.users_tab)
        session_frame.pack(fill="x", padx=PADDING["medium"])

        ctk.CTkLabel(
            session_frame, text="Session Information", font=FONTS["header"]
        ).pack(pady=PADDING["small"])

        # Session status and time remaining
        self.session_info = ctk.CTkLabel(session_frame, text="", font=FONTS["normal"])
        self.session_info.pack(pady=PADDING["small"])

    def update_session_timer(self):
        try:
            current_time = time()
            session_end = current_time + SECURITY["SESSION_DURATION"]
            remaining = session_end - current_time

            if remaining <= SECURITY["WARNING_TIME"]:  # Last minute
                # Show warning dialog
                self.show_session_warning()
            elif remaining > 0:
                # Update timer display
                minutes = int(remaining // SECURITY["WARNING_TIME"])
                seconds = int(remaining % SECURITY["WARNING_TIME"])
                self.session_info.configure(
                    text=f"Session Time Remaining: {minutes}m {seconds}s"
                )
                # Check again in 1 second
                self.window.after(1000, self.update_session_timer)
            else:
                # Session expired
                self.handle_session_end()

        except Exception as e:
            self.show_error(f"Timer error: {str(e)}")

    def show_session_warning(self):
        response = ctk.CTkInputDialog(
            text="Session ending in 1 minute. Type 'EXTEND' to add 1 minute:",
            title="Session Warning",
        ).get_input()

        if response == "EXTEND":
            # Extend session
            self.login_window.password_manager.extend_session()
            self.show_success("Session extended by 1 minute")

    def handle_session_end(self):
        self.show_error("Session expired")
        self.window.withdraw()
        # Show login window again
        self.login_window.deiconify()
