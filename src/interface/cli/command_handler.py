import sys
from pathlib import Path

# Add the core directory to Python's path
core_path = Path(__file__).parent.parent.parent / "core"
sys.path.append(str(core_path))
import password_manager
import pyfiglet
import argparse
from getpass import getpass
import os
import sys
from pathlib import Path

config_path = Path(__file__).parent.parent.parent / "src" / "config"
sys.path.append(str(config_path))
from constants import SECURITY


# CLI aesthetics
ascii_banner = pyfiglet.figlet_format("Vault Of Secrets")
print(ascii_banner)
print("_" * 40)


class Cli:
    """A class for CLI
    Module: argparse
    Arguments: -r (register new user)
               -g (generate password)
               -u (update password)
               -l (define the length of password)
               -s (save the generated password)
               -c (define the category of the pasword)
               -gu (get password by user)
               -gc (get password by category)
               -ga (get all saved passwords)
               -dp (delete password)
               -dc (delete category)
               -cl (clear all passwords)
               -h (programme help)
               -e (extend session)
               -end (end session)
    """

    def __init__(self):
        self.parser = self.parse_arguments()
        self.args = None
        self.password_manager = password_manager.PasswordManager()

    def parse_arguments(self):
        parser = argparse.ArgumentParser(
            prog="Vault Of Secrets",
            description="Encrypted password generator",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""Examples:
            python command_handler.py -r (user_name) (password)
            python command_handler.py -g -l 12 -c social
            python command_handler.py -u -l 12 -c work
            python command_handler.py -gu (user_name)
            python command_handler.py -gc (category)
            python command_handler.py -ga
            python command_handler.py -dc (category)
            python command_handler.py -l (define the length of password)
            python command_handler.py -s (save the generated password)
            python command_handler.py -c (define the category of the pasword)
            python command_handler.py -dp (delete password)
            python command_handler.py -cl (clear all passwords)
            python command_handler.py -h (programme help)
            python command_handler.py -e (extend session)
            python command_handler.py -end (end session) """,
        )
        # Register the first time user
        auth_group = parser.add_argument_group("Authentication")
        auth_group.add_argument(
            "-r", "--register", action="store_true", help="Register new user"
        )
        # Create group of generating password
        generate_group = parser.add_argument_group("Password Generation")
        generate_group.add_argument(
            "-g", "--generate", action="store_true", help="Generate new password"
        )

        generate_group.add_argument(
            "-l",
            "--length",
            type=int,
            default=SECURITY["MIN_LENGTH"],
            help="The length of the password. Default(12)",
        )

        generate_group.add_argument(
            "-c", "--category", help="Choose the category of password"
        )

        # Create a group for retrieve
        retrieve_group = parser.add_argument_group("Password Retrieval")
        retrieve_group.add_argument(
            "-gu", "--get-user", help="Get password by username"
        )
        retrieve_group.add_argument(
            "-gc", "--get-category", help="Get passwords by category"
        )
        retrieve_group.add_argument(
            "-ga", "--get-all", action="store_true", help="Get all passwords"
        )

        # Management group
        manage_group = parser.add_argument_group("Password Management")
        manage_group.add_argument("-dp", "--delpwd", help="Delete a single password.")

        manage_group.add_argument("-dc", "--delcat", help="Delete entire category.")

        manage_group.add_argument(
            "-cl", "--cleall", action="store_true", help="Clear all passwords."
        )

        session_group = parser.add_argument_group("Session Management")
        session_group.add_argument(
            "-e",
            "--extend",
            action="store_true",
            help="Extend current session by 1 minute",
        )
        session_group.add_argument(
            "-end", "--end-session", action="store_true", help="End current session"
        )
        return parser

    def handle_commands(self):
        args = self.parser.parse_args()

        try:
            result = None
            # register new user
            if args.register:
                username = input("New username: ")
                password = getpass("New password: ")
                self.password_manager.register_user(username, password)
                return "Registration successful!"

            # Generate and Save
            elif args.generate:
                password = self.password_manager.generate_new_password(
                    args.length, args.category
                )
                print(f"Generated password: {password}")

            # Retrieval
            elif args.get_user:
                pwd = self.password_manager.get_by_user(args.get_user)
                print(f"Password for {args.get_user}: {pwd}")

            elif args.get_category:
                pwds = self.password_manager.get_by_category(args.get_category)
                print(f"Passwords in {args.get_category}:")
                for pwd in pwds:
                    print(pwd)

            # Management
            elif args.delpwd:
                self.password_manager.delete_password(args.delpwd)
                print("Password deleted successfully")

            elif args.get_all:
                pwds = self.password_manager.get_all()
                print("All passwords:")
                for pwd in pwds:
                    print(pwd)

            elif args.delcat:
                self.password_manager.delete_category(args.delcat)
                print(f"Category {args.delcat} deleted successfully")

            elif args.cleall:
                self.password_manager.clear_all()
                print("All passwords cleared successfully")

            # Session management
            elif args.extend:
                if self.password_manager.extend_session():
                    print("Session extended by 1 minute")
                else:
                    print("Failed to extend session")

            elif args.end_session:
                result = self.password_manager.end_session()
            print(result)

        except Exception as e:
            print(f"Error: {str(e)}")

    def authenticate(self):
        username = input("Username: ")
        password = getpass("Password: ")
        self.password_manager.start_session(username, password)


if __name__ == "__main__":
    ascii_banner = pyfiglet.figlet_format("Vault Of Secrets CLI")
    print(ascii_banner)
    print("_" * 40)

    cli = Cli()
    while True:
        print("1. Login")
        print("2. Register")
        print("3. Show Commands")  # Add help option
        print("4. Exit")

        choice = input("Choose option (1-4): ")

        if choice == "1":
            if cli.authenticate():
                print("\nAvailable commands:")
                print("-g  : Generate password")
                print("-ga : Get all passwords")
                print("-gc : Get passwords by category")
                print("-dp : Delete password")
                print("-h  : Show help")

                while True:  # Command loop after login
                    command = input("\nEnter command (or 'exit' to quit): ")
                    if command.lower() == "exit":
                        break

                    sys.argv = [sys.argv[0]] + command.split()
                    result = cli.handle_commands()
                    if result:
                        print(result)

        elif choice == "2":
            sys.argv = [sys.argv[0], "-r"]
            result = cli.handle_commands()
            print(result)

        elif choice == "3":
            sys.argv = [sys.argv[0], "-h"]
            cli.handle_commands()

        elif choice == "4":
            print("Goodbye!")
            sys.exit(0)
