import os
import sys
from pathlib import Path

# Add src to Python path
src_path = Path(__file__).parent / "src"
sys.path.append(str(src_path))
from interface.gui.login_window import LoginWindow
from interface.cli.command_handler import Cli
import pyfiglet


def clear_screen():
    # If Windows ('nt'), use 'cls'
    # If Linux/Mac ('posix'), use 'clear'
    os.system("cls" if os.name == "nt" else "clear")


VERSION = "1.0.0"


def main():
    display_banner()
    print("""
    ╔════════════════════════════╗
    ║    Vault of Secrets        ║
    ║         v1.0.0            ║
    ╠════════════════════════════╣
    ║ 1. Graphical Interface     ║
    ║ 2. Command Line Interface  ║
    ║ 3. Exit                    ║
    ╚════════════════════════════╝
    """)

    choice = get_interface_choice()

    if choice == "1":
        print("Starting GUI interface...")
        app = LoginWindow()
        app.window.mainloop()
    elif choice == "2":
        handle_cli_mode()
    else:
        print("Goodbye!")
        sys.exit(0)

def display_banner() -> None:
    """Display the ASCII art banner."""
    ascii_banner = pyfiglet.figlet_format("Vault Of Secrets")
    print(ascii_banner)
    print("_" * 40)

def get_interface_choice() -> str:
    """Get user interface choice."""
    while True:
        choice = input("Select interface (1-3): ")
        if choice in ["1", "2", "3"]:
            return choice
        print("Invalid choice. Please select 1-3")

def handle_cli_mode() -> None:
    """Handle CLI interface operations."""
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


if __name__ == "__main__":
    main()
