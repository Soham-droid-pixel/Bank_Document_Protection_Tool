# bank_document_protector.py
"""
Bank Document Protection Tool
A production-ready desktop application for password-protecting PDF and Excel files
Designed for banking and financial institutions with security best practices.

Author: Bank IT Security Team
Version: 1.0.0
License: Proprietary - Internal Bank Use Only
"""

import os
import sys
import logging
import getpass
import hashlib
import secrets
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from dataclasses import dataclass
import argparse

# Third-party imports
try:
    import pypdf
    from pypdf import PdfWriter, PdfReader
    import xlsxwriter
    import keyring
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    import base64
except ImportError as e:
    print(f"Missing required dependency: {e}")
    print("Please install required packages:")
    print("pip install pypdf xlsxwriter keyring cryptography")
    sys.exit(1)

# GUI imports (optional)
try:
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False


@dataclass
class DocumentProtectionRequest:
    """Data class for document protection requests"""
    file_type: str
    input_path: Path
    output_path: Path
    user_password: str
    owner_password: Optional[str] = None
    content_data: Optional[Dict[str, Any]] = None


class SecurityManager:
    """Handles security operations and password management"""
    
    def __init__(self):
        self.service_name = "BankDocProtector"
        
    def generate_secure_password(self, length: int = 16) -> str:
        """Generate a cryptographically secure password"""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def hash_password(self, password: str) -> str:
        """Create a secure hash of the password for logging/audit purposes"""
        return hashlib.sha256(password.encode()).hexdigest()[:16]
    
    def store_password_securely(self, username: str, password: str) -> bool:
        """Store password in Windows Credential Manager"""
        try:
            keyring.set_password(self.service_name, username, password)
            return True
        except Exception as e:
            logging.error(f"Failed to store password securely: {e}")
            return False
    
    def retrieve_password_securely(self, username: str) -> Optional[str]:
        """Retrieve password from Windows Credential Manager"""
        try:
            return keyring.get_password(self.service_name, username)
        except Exception as e:
            logging.error(f"Failed to retrieve password securely: {e}")
            return None
    
    def validate_password_strength(self, password: str) -> tuple[bool, str]:
        """Validate password meets bank security requirements"""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        missing = []
        if not has_upper:
            missing.append("uppercase letter")
        if not has_lower:
            missing.append("lowercase letter")
        if not has_digit:
            missing.append("digit")
        if not has_special:
            missing.append("special character")
        
        if missing:
            return False, f"Password must contain: {', '.join(missing)}"
        
        return True, "Password meets security requirements"


class AuditLogger:
    """Handles secure logging and audit trails"""
    
    def __init__(self, log_file: str = "bank_doc_protector.log"):
        self.log_file = Path(log_file)
        self.setup_logging()
    
    def setup_logging(self):
        """Configure secure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Ensure log file has restricted permissions
        if self.log_file.exists():
            os.chmod(self.log_file, 0o600)  # Read/write for owner only
    
    def log_protection_attempt(self, request: DocumentProtectionRequest, success: bool, error: str = None):
        """Log document protection attempts (without exposing passwords)"""
        password_hash = hashlib.sha256(request.user_password.encode()).hexdigest()[:16]
        
        log_data = {
            "operation": "document_protection",
            "file_type": request.file_type,
            "input_file": str(request.input_path),
            "output_file": str(request.output_path),
            "password_hash": password_hash,
            "success": success,
            "user": os.getenv('USERNAME', 'unknown'),
            "machine": os.getenv('COMPUTERNAME', 'unknown')
        }
        
        if error:
            log_data["error"] = error
        
        if success:
            logging.info(f"Document protection successful: {log_data}")
        else:
            logging.error(f"Document protection failed: {log_data}")


class PDFProtector:
    """Handles PDF encryption and protection"""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
    
    def protect_pdf(self, request: DocumentProtectionRequest) -> tuple[bool, str]:
        """Encrypt PDF file with password protection"""
        try:
            if not request.input_path.exists():
                return False, f"Input file does not exist: {request.input_path}"
            
            if not request.input_path.suffix.lower() == '.pdf':
                return False, "Input file must be a PDF"
            
            # Read the input PDF
            with open(request.input_path, 'rb') as input_file:
                reader = PdfReader(input_file)
                writer = PdfWriter()
                
                # Copy all pages
                for page in reader.pages:
                    writer.add_page(page)
                
                # Apply encryption
                writer.encrypt(
                    user_password=request.user_password,
                    owner_password=request.owner_password or request.user_password,
                    use_128bit=True,
                    permissions_flag=-1  # All permissions for owner
                )
                
                # Ensure output directory exists
                request.output_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Write the encrypted PDF
                with open(request.output_path, 'wb') as output_file:
                    writer.write(output_file)
            
            # Set restrictive file permissions
            os.chmod(request.output_path, 0o600)
            
            self.audit_logger.log_protection_attempt(request, True)
            return True, f"PDF successfully encrypted and saved to {request.output_path}"
            
        except Exception as e:
            error_msg = f"Failed to encrypt PDF: {str(e)}"
            self.audit_logger.log_protection_attempt(request, False, error_msg)
            return False, error_msg


class ExcelProtector:
    """Handles Excel file encryption and protection"""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
    
    def protect_excel(self, request: DocumentProtectionRequest) -> tuple[bool, str]:
        """Create password-protected Excel file"""
        try:
            # Ensure output directory exists
            request.output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Create workbook with password protection
            workbook_options = {
                'options': {
                    'strings_to_numbers': True,
                    'strings_to_formulas': True,
                    'strings_to_urls': False
                }
            }
            
            workbook = xlsxwriter.Workbook(str(request.output_path), workbook_options)
            
            # Set workbook password protection
            workbook.set_properties({
                'title': 'Protected Bank Document',
                'subject': 'Confidential Banking Information',
                'author': f'Bank System - {os.getenv("USERNAME", "System")}',
                'company': 'Bank IT Security',
                'created': datetime.now()
            })
            
            # Create worksheet
            worksheet = workbook.add_worksheet('Bank_Data')
            
            # Define formats
            header_format = workbook.add_format({
                'bold': True,
                'font_color': 'white',
                'bg_color': '#1f4e79',
                'border': 1,
                'align': 'center'
            })
            
            cell_format = workbook.add_format({
                'border': 1,
                'align': 'left'
            })
            
            # Add content based on request data
            if request.content_data:
                self._populate_excel_content(worksheet, request.content_data, header_format, cell_format)
            else:
                # Default banking template
                self._create_default_banking_template(worksheet, header_format, cell_format)
            
            # Protect worksheet with password
            worksheet.protect(request.user_password, {
                'select_locked_cells': True,
                'select_unlocked_cells': True,
                'format_cells': False,
                'format_columns': False,
                'format_rows': False,
                'insert_columns': False,
                'insert_rows': False,
                'insert_hyperlinks': False,
                'delete_columns': False,
                'delete_rows': False,
                'sort': False,
                'autofilter': False,
                'pivot_tables': False,
                'objects': False,
                'scenarios': False
            })
            
            workbook.close()
            
            # Set restrictive file permissions
            os.chmod(request.output_path, 0o600)
            
            self.audit_logger.log_protection_attempt(request, True)
            return True, f"Excel file successfully created and protected: {request.output_path}"
            
        except Exception as e:
            error_msg = f"Failed to create protected Excel file: {str(e)}"
            self.audit_logger.log_protection_attempt(request, False, error_msg)
            return False, error_msg
    
    def _populate_excel_content(self, worksheet, content_data: Dict[str, Any], header_format, cell_format):
        """Populate Excel with provided content data"""
        row = 0
        for key, value in content_data.items():
            worksheet.write(row, 0, key, header_format)
            worksheet.write(row, 1, str(value), cell_format)
            row += 1
    
    def _create_default_banking_template(self, worksheet, header_format, cell_format):
        """Create default banking document template"""
        headers = ['Field', 'Value']
        data = [
            ['Document Type', 'Bank Statement'],
            ['Account Number', '[PROTECTED]'],
            ['Account Holder', '[PROTECTED]'],
            ['Statement Period', datetime.now().strftime('%Y-%m')],
            ['Opening Balance', '[PROTECTED]'],
            ['Closing Balance', '[PROTECTED]'],
            ['Generated On', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Security Level', 'CONFIDENTIAL']
        ]
        
        # Write headers
        for col, header in enumerate(headers):
            worksheet.write(0, col, header, header_format)
        
        # Write data
        for row, (field, value) in enumerate(data, 1):
            worksheet.write(row, 0, field, cell_format)
            worksheet.write(row, 1, value, cell_format)
        
        # Auto-fit columns
        worksheet.set_column('A:A', 20)
        worksheet.set_column('B:B', 25)


class DocumentProtector:
    """Main document protection service"""
    
    def __init__(self):
        self.audit_logger = AuditLogger()
        self.security_manager = SecurityManager()
        self.pdf_protector = PDFProtector(self.audit_logger)
        self.excel_protector = ExcelProtector(self.audit_logger)
    
    def protect_document(self, request: DocumentProtectionRequest) -> tuple[bool, str]:
        """Main method to protect documents based on type"""
        # Validate password strength
        is_valid, message = self.security_manager.validate_password_strength(request.user_password)
        if not is_valid:
            return False, f"Password validation failed: {message}"
        
        if request.file_type.lower() == 'pdf':
            return self.pdf_protector.protect_pdf(request)
        elif request.file_type.lower() == 'excel':
            return self.excel_protector.protect_excel(request)
        else:
            return False, f"Unsupported file type: {request.file_type}"


class CLIInterface:
    """Command-line interface for the document protector"""
    
    def __init__(self):
        self.protector = DocumentProtector()
    
    def run(self):
        """Run the CLI interface"""
        parser = argparse.ArgumentParser(
            description="Bank Document Protection Tool - Secure PDF and Excel files",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  python bank_document_protector.py --type pdf --input report.pdf --output secure_report.pdf
  python bank_document_protector.py --type excel --output statement.xlsx --interactive
  python bank_document_protector.py --gui
            """
        )
        
        parser.add_argument('--type', choices=['pdf', 'excel'], help='Document type to protect')
        parser.add_argument('--input', type=Path, help='Input file path (for PDF protection)')
        parser.add_argument('--output', type=Path, help='Output file path')
        parser.add_argument('--interactive', action='store_true', help='Interactive mode')
        parser.add_argument('--gui', action='store_true', help='Launch GUI interface')
        parser.add_argument('--generate-password', action='store_true', help='Generate secure password')
        
        args = parser.parse_args()
        
        if args.gui:
            if GUI_AVAILABLE:
                gui = GUIInterface()
                gui.run()
            else:
                print("GUI not available. Install tkinter to use GUI mode.")
                return
        
        if args.generate_password:
            password = self.protector.security_manager.generate_secure_password()
            print(f"Generated secure password: {password}")
            return
        
        if args.interactive or not all([args.type, args.output]):
            self.run_interactive_mode()
        else:
            self.run_batch_mode(args)
    
    def run_interactive_mode(self):
        """Run interactive CLI mode"""
        print("=== Bank Document Protection Tool ===")
        print("Select document type:")
        print("1. PDF Protection")
        print("2. Excel Creation")
        
        choice = input("Enter choice (1-2): ").strip()
        
        if choice == '1':
            self.handle_pdf_protection()
        elif choice == '2':
            self.handle_excel_creation()
        else:
            print("Invalid choice")
    
    def handle_pdf_protection(self):
        """Handle PDF protection in interactive mode"""
        input_path = Path(input("Enter input PDF path: ").strip())
        output_path = Path(input("Enter output PDF path: ").strip())
        
        user_password = getpass.getpass("Enter user password: ")
        owner_password = getpass.getpass("Enter owner password (press Enter for same as user): ")
        
        if not owner_password:
            owner_password = user_password
        
        request = DocumentProtectionRequest(
            file_type='pdf',
            input_path=input_path,
            output_path=output_path,
            user_password=user_password,
            owner_password=owner_password
        )
        
        success, message = self.protector.protect_document(request)
        print(f"Result: {message}")
    
    def handle_excel_creation(self):
        """Handle Excel creation in interactive mode"""
        output_path = Path(input("Enter output Excel path: ").strip())
        password = getpass.getpass("Enter protection password: ")
        
        print("Enter content data (press Enter on empty field to finish):")
        content_data = {}
        while True:
            field = input("Field name: ").strip()
            if not field:
                break
            value = input(f"Value for {field}: ").strip()
            content_data[field] = value
        
        request = DocumentProtectionRequest(
            file_type='excel',
            input_path=Path(),  # Not needed for Excel creation
            output_path=output_path,
            user_password=password,
            content_data=content_data if content_data else None
        )
        
        success, message = self.protector.protect_document(request)
        print(f"Result: {message}")
    
    def run_batch_mode(self, args):
        """Run in batch mode with command line arguments"""
        if args.type == 'pdf' and not args.input:
            print("Error: Input file required for PDF protection")
            return
        
        password = getpass.getpass("Enter protection password: ")
        
        request = DocumentProtectionRequest(
            file_type=args.type,
            input_path=args.input or Path(),
            output_path=args.output,
            user_password=password,
            owner_password=password if args.type == 'pdf' else None
        )
        
        success, message = self.protector.protect_document(request)
        print(f"Result: {message}")


class GUIInterface:
    """Graphical user interface for the document protector"""
    
    def __init__(self):
        self.protector = DocumentProtector()
        self.root = tk.Tk()
        self.setup_gui()
    
    def setup_gui(self):
        """Setup the GUI interface"""
        self.root.title("Bank Document Protection Tool v1.0")
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        
        # Configure style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Create main notebook for tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # PDF Protection Tab
        pdf_frame = ttk.Frame(notebook)
        notebook.add(pdf_frame, text="PDF Protection")
        self.setup_pdf_tab(pdf_frame)
        
        # Excel Creation Tab
        excel_frame = ttk.Frame(notebook)
        notebook.add(excel_frame, text="Excel Creation")
        self.setup_excel_tab(excel_frame)
        
        # Security Tab
        security_frame = ttk.Frame(notebook)
        notebook.add(security_frame, text="Security Tools")
        self.setup_security_tab(security_frame)
    
    def setup_pdf_tab(self, parent):
        """Setup PDF protection tab"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Input file selection
        ttk.Label(main_frame, text="Input PDF File:").pack(anchor='w')
        input_frame = ttk.Frame(main_frame)
        input_frame.pack(fill='x', pady=(0, 10))
        
        self.pdf_input_var = tk.StringVar()
        ttk.Entry(input_frame, textvariable=self.pdf_input_var, width=60).pack(side='left', fill='x', expand=True)
        ttk.Button(input_frame, text="Browse", command=self.browse_pdf_input).pack(side='right', padx=(5, 0))
        
        # Output file selection
        ttk.Label(main_frame, text="Output PDF File:").pack(anchor='w')
        output_frame = ttk.Frame(main_frame)
        output_frame.pack(fill='x', pady=(0, 10))
        
        self.pdf_output_var = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.pdf_output_var, width=60).pack(side='left', fill='x', expand=True)
        ttk.Button(output_frame, text="Browse", command=self.browse_pdf_output).pack(side='right', padx=(5, 0))
        
        # Password fields
        ttk.Label(main_frame, text="User Password:").pack(anchor='w')
        self.pdf_user_password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.pdf_user_password_var, show="*", width=40).pack(anchor='w', pady=(0, 10))
        
        ttk.Label(main_frame, text="Owner Password (optional):").pack(anchor='w')
        self.pdf_owner_password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.pdf_owner_password_var, show="*", width=40).pack(anchor='w', pady=(0, 20))
        
        # Protect button
        ttk.Button(main_frame, text="Protect PDF", command=self.protect_pdf).pack(pady=10)
        
        # Status text
        self.pdf_status_text = tk.Text(main_frame, height=10, width=80)
        self.pdf_status_text.pack(fill='both', expand=True, pady=(10, 0))
        
        # Scrollbar for status text
        scrollbar = ttk.Scrollbar(self.pdf_status_text)
        scrollbar.pack(side='right', fill='y')
        self.pdf_status_text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.pdf_status_text.yview)
    
    def setup_excel_tab(self, parent):
        """Setup Excel creation tab"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Output file selection
        ttk.Label(main_frame, text="Output Excel File:").pack(anchor='w')
        output_frame = ttk.Frame(main_frame)
        output_frame.pack(fill='x', pady=(0, 10))
        
        self.excel_output_var = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.excel_output_var, width=60).pack(side='left', fill='x', expand=True)
        ttk.Button(output_frame, text="Browse", command=self.browse_excel_output).pack(side='right', padx=(5, 0))
        
        # Password field
        ttk.Label(main_frame, text="Protection Password:").pack(anchor='w')
        self.excel_password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.excel_password_var, show="*", width=40).pack(anchor='w', pady=(0, 20))
        
        # Content data frame
        ttk.Label(main_frame, text="Content Data (Field = Value):").pack(anchor='w')
        content_frame = ttk.Frame(main_frame)
        content_frame.pack(fill='both', expand=True, pady=(0, 20))
        
        # Create treeview for content data
        columns = ('Field', 'Value')
        self.excel_content_tree = ttk.Treeview(content_frame, columns=columns, show='headings', height=8)
        self.excel_content_tree.heading('Field', text='Field')
        self.excel_content_tree.heading('Value', text='Value')
        self.excel_content_tree.column('Field', width=200)
        self.excel_content_tree.column('Value', width=300)
        self.excel_content_tree.pack(side='left', fill='both', expand=True)
        
        # Scrollbar for treeview
        tree_scrollbar = ttk.Scrollbar(content_frame, orient='vertical', command=self.excel_content_tree.yview)
        tree_scrollbar.pack(side='right', fill='y')
        self.excel_content_tree.configure(yscrollcommand=tree_scrollbar.set)
        
        # Add/Remove buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Button(button_frame, text="Add Row", command=self.add_excel_row).pack(side='left', padx=(0, 5))
        ttk.Button(button_frame, text="Remove Row", command=self.remove_excel_row).pack(side='left', padx=(0, 5))
        ttk.Button(button_frame, text="Load Default Template", command=self.load_default_template).pack(side='left')
        
        # Create button
        ttk.Button(main_frame, text="Create Protected Excel", command=self.create_excel).pack(pady=10)
        
        # Status text
        self.excel_status_text = tk.Text(main_frame, height=6, width=80)
        self.excel_status_text.pack(fill='x', pady=(10, 0))
    
    def setup_security_tab(self, parent):
        """Setup security tools tab"""
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Password generator
        ttk.Label(main_frame, text="Password Generator", font=('TkDefaultFont', 12, 'bold')).pack(anchor='w', pady=(0, 10))
        
        gen_frame = ttk.Frame(main_frame)
        gen_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Label(gen_frame, text="Length:").pack(side='left')
        self.password_length_var = tk.StringVar(value="16")
        ttk.Entry(gen_frame, textvariable=self.password_length_var, width=5).pack(side='left', padx=(5, 10))
        
        ttk.Button(gen_frame, text="Generate Password", command=self.generate_password).pack(side='left')
        
        self.generated_password_var = tk.StringVar()
        ttk.Entry(main_frame, textvariable=self.generated_password_var, width=60, state='readonly').pack(anchor='w', pady=(0, 20))
        
        # Password validation
        ttk.Label(main_frame, text="Password Validator", font=('TkDefaultFont', 12, 'bold')).pack(anchor='w', pady=(10, 10))
        
        ttk.Label(main_frame, text="Test Password:").pack(anchor='w')
        self.test_password_var = tk.StringVar()
        test_frame = ttk.Frame(main_frame)
        test_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Entry(test_frame, textvariable=self.test_password_var, show="*", width=40).pack(side='left')
        ttk.Button(test_frame, text="Validate", command=self.validate_password).pack(side='left', padx=(10, 0))
        
        self.validation_result_text = tk.Text(main_frame, height=4, width=80)
        self.validation_result_text.pack(fill='x', pady=(10, 0))
    
    def browse_pdf_input(self):
        """Browse for input PDF file"""
        file_path = filedialog.askopenfilename(
            title="Select PDF file to protect",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if file_path:
            self.pdf_input_var.set(file_path)
    
    def browse_pdf_output(self):
        """Browse for output PDF file"""
        file_path = filedialog.asksaveasfilename(
            title="Save protected PDF as",
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
        )
        if file_path:
            self.pdf_output_var.set(file_path)
    
    def browse_excel_output(self):
        """Browse for output Excel file"""
        file_path = filedialog.asksaveasfilename(
            title="Save Excel file as",
            defaultextension=".xlsx",
            filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")]
        )
        if file_path:
            self.excel_output_var.set(file_path)
    
    def protect_pdf(self):
        """Protect PDF file"""
        try:
            input_path = self.pdf_input_var.get()
            output_path = self.pdf_output_var.get()
            user_password = self.pdf_user_password_var.get()
            owner_password = self.pdf_owner_password_var.get()
            
            if not all([input_path, output_path, user_password]):
                messagebox.showerror("Error", "Please fill in all required fields")
                return
            
            request = DocumentProtectionRequest(
                file_type='pdf',
                input_path=Path(input_path),
                output_path=Path(output_path),
                user_password=user_password,
                owner_password=owner_password if owner_password else user_password
            )
            
            success, message = self.protector.protect_document(request)
            
            self.pdf_status_text.delete(1.0, tk.END)
            self.pdf_status_text.insert(tk.END, f"{datetime.now()}: {message}\n")
            
            if success:
                messagebox.showinfo("Success", "PDF protected successfully!")
            else:
                messagebox.showerror("Error", message)
                
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def add_excel_row(self):
        """Add row to Excel content data"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Content Row")
        dialog.geometry("400x150")
        dialog.resizable(False, False)
        
        # Center the dialog
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Field input
        ttk.Label(dialog, text="Field:").pack(pady=5)
        field_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=field_var, width=40).pack(pady=5)
        
        # Value input
        ttk.Label(dialog, text="Value:").pack(pady=5)
        value_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=value_var, width=40).pack(pady=5)
        
        # Buttons
        button_frame = ttk.Frame(dialog)
        button_frame.pack(pady=10)
        
        def add_row():
            field = field_var.get().strip()
            value = value_var.get().strip()
            if field and value:
                self.excel_content_tree.insert('', 'end', values=(field, value))
                dialog.destroy()
            else:
                messagebox.showerror("Error", "Please fill in both field and value")
        
        ttk.Button(button_frame, text="Add", command=add_row).pack(side='left', padx=5)
        ttk.Button(button_frame, text="Cancel", command=dialog.destroy).pack(side='left', padx=5)
    
    def remove_excel_row(self):
        """Remove selected row from Excel content data"""
        selected_item = self.excel_content_tree.selection()
        if selected_item:
            self.excel_content_tree.delete(selected_item)
        else:
            messagebox.showwarning("Warning", "Please select a row to remove")
    
    def load_default_template(self):
        """Load default banking template"""
        # Clear existing data
        for item in self.excel_content_tree.get_children():
            self.excel_content_tree.delete(item)
        
        # Add default banking fields
        default_data = [
            ('Document Type', 'Bank Statement'),
            ('Account Number', '[PROTECTED]'),
            ('Account Holder', '[PROTECTED]'),
            ('Statement Period', datetime.now().strftime('%Y-%m')),
            ('Opening Balance', '[PROTECTED]'),
            ('Closing Balance', '[PROTECTED]'),
            ('Generated On', datetime.now().strftime('%Y-%m-%d %H:%M:%S')),
            ('Security Level', 'CONFIDENTIAL'),
            ('Branch Code', '[PROTECTED]'),
            ('Transaction Count', '[PROTECTED]')
        ]
        
        for field, value in default_data:
            self.excel_content_tree.insert('', 'end', values=(field, value))
    
    def create_excel(self):
        """Create protected Excel file"""
        try:
            output_path = self.excel_output_var.get()
            password = self.excel_password_var.get()
            
            if not all([output_path, password]):
                messagebox.showerror("Error", "Please provide output path and password")
                return
            
            # Collect content data from treeview
            content_data = {}
            for item in self.excel_content_tree.get_children():
                values = self.excel_content_tree.item(item, 'values')
                if len(values) == 2:
                    content_data[values[0]] = values[1]
            
            request = DocumentProtectionRequest(
                file_type='excel',
                input_path=Path(),
                output_path=Path(output_path),
                user_password=password,
                content_data=content_data if content_data else None
            )
            
            success, message = self.protector.protect_document(request)
            
            self.excel_status_text.delete(1.0, tk.END)
            self.excel_status_text.insert(tk.END, f"{datetime.now()}: {message}\n")
            
            if success:
                messagebox.showinfo("Success", "Excel file created and protected successfully!")
            else:
                messagebox.showerror("Error", message)
                
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")
    
    def generate_password(self):
        """Generate secure password"""
        try:
            length = int(self.password_length_var.get())
            if length < 8:
                messagebox.showerror("Error", "Password length must be at least 8 characters")
                return
            
            password = self.protector.security_manager.generate_secure_password(length)
            self.generated_password_var.set(password)
            
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for password length")
    
    def validate_password(self):
        """Validate password strength"""
        password = self.test_password_var.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password to validate")
            return
        
        is_valid, message = self.protector.security_manager.validate_password_strength(password)
        
        self.validation_result_text.delete(1.0, tk.END)
        
        result_text = f"Password Validation Result:\n"
        result_text += f"Status: {'VALID' if is_valid else 'INVALID'}\n"
        result_text += f"Message: {message}\n"
        result_text += f"Length: {len(password)} characters\n"
        
        if is_valid:
            result_text += "✓ This password meets bank security requirements"
        else:
            result_text += "✗ This password does not meet security requirements"
        
        self.validation_result_text.insert(tk.END, result_text)
    
    def run(self):
        """Run the GUI application"""
        # Set window icon (if available)
        try:
            # You can add an icon file here
            # self.root.iconbitmap('bank_icon.ico')
            pass
        except:
            pass
        
        # Center the window
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")
        
        # Add status bar
        status_bar = ttk.Label(self.root, text="Ready | Bank Document Protection Tool v1.0", relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Start the GUI
        self.root.mainloop()


def main():
    """Main entry point for the application"""
    print("Bank Document Protection Tool v1.0")
    print("=" * 50)
    
    # Check if running with arguments
    if len(sys.argv) > 1:
        cli = CLIInterface()
        cli.run()
    else:
        # Interactive mode selection
        print("Select interface:")
        print("1. Command Line Interface (CLI)")
        print("2. Graphical User Interface (GUI)")
        print("3. Interactive CLI Mode")
        
        choice = input("Enter choice (1-3): ").strip()
        
        if choice == '1':
            print("Use --help for command line options")
            print("Example: python bank_document_protector.py --type pdf --input file.pdf --output secure.pdf")
        elif choice == '2':
            if GUI_AVAILABLE:
                gui = GUIInterface()
                gui.run()
            else:
                print("GUI not available. Please install tkinter.")
                print("Falling back to CLI mode...")
                cli = CLIInterface()
                cli.run_interactive_mode()
        elif choice == '3':
            cli = CLIInterface()
            cli.run_interactive_mode()
        else:
            print("Invalid choice. Exiting.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)