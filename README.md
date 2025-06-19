# 🏦 Bank Document Protection Tool

A secure, production-ready desktop application for password-protecting PDF and Excel files, designed specifically for banking and financial institutions. 🔐

## ✨ Features

- **📄 PDF Protection**: Encrypt existing PDF files with user and owner passwords
- **📊 Excel Creation**: Generate password-protected Excel files with banking templates
- **🔒 Security Tools**: Password generation and validation with bank-grade requirements
- **🖥️ Multiple Interfaces**: Command-line, interactive CLI, and GUI options
- **📝 Audit Logging**: Comprehensive logging for security compliance
- **💾 Secure Storage**: Windows Credential Manager integration

## 🚀 Quick Start

### 📥 Installation

1. Run the automated installer:
   ```bash
   install.bat
   ```

2. Or install manually:
   ```bash
   pip install pypdf xlsxwriter keyring cryptography
   pip install tkinter  # For GUI support (usually pre-installed)
   ```

### 💻 Usage

**🖼️ GUI Mode (Recommended)**
```bash
python bank_document_protector.py --gui
```

**⌨️ Command Line**
```bash
# Protect a PDF
python bank_document_protector.py --type pdf --input report.pdf --output secure_report.pdf

# Create protected Excel
python bank_document_protector.py --type excel --output statement.xlsx
```

**💬 Interactive Mode**
```bash
python bank_document_protector.py --interactive
```

## 📁 File Structure

```
├── 🐍 bank_document_protector.py    # Main application
├── ⚙️ config.py                     # Configuration settings
├── 🚀 install.bat                   # Automated installer
├── 📖 README.md                     # This file
└── 📋 bank_doc_protector.log        # Generated log file
```

## 🛡️ Security Features

- **🔐 Password Requirements**: Enforces 8+ characters with mixed case, numbers, and special characters
- **📊 Secure Logging**: Audit trails without exposing sensitive data
- **🔒 File Permissions**: Restricts access to protected files (owner-only)
- **💳 Credential Management**: Secure password storage using Windows Credential Manager

## ⚙️ Configuration

Edit `config.py` to customize:
- 📂 Default file paths
- 🔑 Password complexity requirements
- 📝 Logging levels
- 🛡️ Security settings

## 📋 Requirements

- 🐍 Python 3.7+
- 🪟 Windows OS (for credential manager features)
- 📦 Required packages: pypdf, xlsxwriter, keyring, cryptography
- 🎨 Optional: tkinter (for GUI)

## 📄 License

🏢 Proprietary - Internal Bank Use Only

---

**📌 Version**: 1.0.0  
**👨‍💻 Author**: Bank IT Security Team
