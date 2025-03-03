# **Vault of Secrets**

## **Description:**
Vault of Secrets is a Python-based secure password manager that provides robust password generation, encryption, and storage capabilities. Built with a focus on security and usability, it offers both GUI and CLI interfaces while implementing industry-standard security practices.

## **Features**
- Secure password generation following NIST guidelines
- AES encryption with Argon2 key derivation
- Multi-layered authentication system
- Session management with timeout controls
- Category-based password organization
- Comprehensive logging system
- Both GUI (CustomTkinter) and CLI interfaces
- Input validation and error handling
- Secure data storage using SQLite

## **Project Structure**
vault_of_secrets/
├── src/
│   ├── core/
│   │   ├── password_generator.py  # Secure password generation
│   │   ├── encryption.py         # Encryption operations
│   │   ├── database.py          # Secure storage
│   │   ├── auth.py              # Authentication system
│   │   └── password_manager.py  # Core coordinator
│   ├── interface/
│   │   ├── gui/                 # GUI implementation
│   │   └── cli/                 # CLI implementation
│   ├── config/                  # Configuration
│   └── utils/                   # Utilities
├── tests/                       # Unit tests
├── main.py                      # Application entry point
├── config.ini                   # Configuration settings
└── README.md

## **Technologies Used**
Python 3.11 and VS Code

### **Core Libraries:**

- argparse for CLI argument parsing
- sqlite3 for secure database operations
- secrets for cryptographic operations
- time for session management
- csv for session data handling
- contextlib for database management

### **Security Libraries:**

- cryptography for AES encryption
- argon2-cffi for password hashing
- bcrypt for secure password handling

### **GUI Libraries:**

- customtkinter for modern GUI interface

- Black for formatting.

## **Usage**

### **Command Line Interface**
```bash
# Generate and store password
python main.py -g -l 16 -c social

# View passwords by category
python main.py -gc work

# View all stored passwords
python main.py -ga

# Delete specific password
python main.py -dp password_id
```

### **GUI Interface**
```bash
python main.py
```

### **The GUI provides:**

- Login/Registration interface
- Password generation with category assignment
- Password viewing and management
- Session management with timeout warnings
- Category-based organization

### **Configuration**

Edit config.ini to customize:
```ini
[Security]
min_length = 12
session_duration = 300
warning_time = 60

[Database]
path = vault.db
```
## **Security Features**

### **Password Generation:**

- Cryptographically secure random generation
- Minimum length enforcement (12 characters)
- Mix of uppercase, lowercase, numbers, and special characters
- Using Python's secrets module for true randomness

### **Authentication System:**

- Argon2 password hashing
- Session management with timeouts
- Automatic session termination
- Extension warnings and options
- Secure session data handling

### **Data Protection:**

- AES encryption for stored passwords
- Encrypted database storage
- Secure memory handling
- File scrambling on session end
- Database health monitoring

### **Input Validation:**

- Username format validation
- Password length verification
- Category name validation
- Database integrity checks

## **Design Choices**

### **Modular Architecture:**

- Separate core modules for distinct responsibilities
- Clean interfaces between components
- Easy testing and maintenance
- Clear dependency management

### **Security First:**

- No stored plaintext passwords
- Session-based authentication
- Secure default settings
- Comprehensive error handling

### **Dual Interface:**

- GUI for user-friendly operation
- CLI for automation and scripts
- Consistent security across interfaces
- Shared core functionality

### **Data Management:**

- Category-based organization
- Efficient database operations
- Secure CRUD operations
- Transaction management

## **How to Test**

### **Unit Tests:**
```bash
# Run all tests
pytest tests/

# Test specific modules
pytest tests/test_password_generator.py
pytest tests/test_auth.py
```

### **Basic Usage Test:**
```bash
# Register new user
python main.py -r

# Generate password
python main.py -g -l 16 -c social

# View passwords
python main.py -ga
```

### **GUI Testing:**
```bash
python main.py
# Follow login/registration prompts
# Test password generation and management
```
## **Areas for Improvement**

### **Feature Enhancements:**

- Password strength meter
- Password expiration notifications
- Backup and restore functionality
- Import/export capabilities
- Multiple user profiles

### **Security Additions:**

- Two-factor authentication
- Biometric authentication integration
- Enhanced session management
- Secure password sharing

### **Interface Improvements:**

- More customization options
- Dark/light theme support
- Mobile interface
- Browser extension

### **Technical Enhancements:**

- Cloud synchronization
- Enhanced logging capabilities
- Performance optimizations
- Additional export formats

## **Credits and Acknowledgements**

- CS50x course staff and community, especially David J Malan.

## **Useful resources**

- Python Programming documentation and communities.
- CS50P course by David J malan.
- CS50x course by David J malan.
- PYPI the python packages index.
- Claude AI for brainstorming, arrange project phases, and some code reviews.
- Claude AI for scientific explanation, and establishing of this readme file.
- CS Duck for debugging help.
- YouTube channels. 
- Grammarly for grammar review of this file.
- stack overflow and geeks for geeks blogs for various researchings.
- customtkinter website.
- Argon2 website.
- Python security best practices resources

## **License**

This project is released under the MIT License. See LICENSE file for details.

## Author

[Ahmed Ibraheem]
GitHub: [@AhmadElsisy]

## **Disclaimer**

# **IMPORTANT SECURITY NOTICE:**

**This password manager is provided "as is" without any warranties. While it implements various security measures:**

1. **Security Considerations:**

- Always use a strong master password
- Keep your system and Python environment updated
- Regularly backup your password database
- Never share your master password

2. **Usage Responsibility:**

- The user is responsible for maintaining the security of their master password
- Regular security updates and maintenance are recommended
- The developer is not responsible for any data loss or security breaches
- Use at your own risk

3. **Data Protection:**

- While this software implements encryption and security measures
No software can guarantee 100% security
- Always follow good security practices
- Consider this as one part of your overall security strategy
- By using this software, you acknowledge these risks and responsibilities.

End of Documentation 🔒