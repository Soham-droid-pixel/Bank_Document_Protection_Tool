# config.py
"""
Configuration management for Bank Document Protection Tool
Handles environment variables, security settings, and application configuration
"""

import os
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class SecurityConfig:
    """Security configuration settings"""
    min_password_length: int = 8
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True
    require_special_chars: bool = True
    allowed_special_chars: str = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    max_password_attempts: int = 3
    session_timeout_minutes: int = 30
    enable_audit_logging: bool = True
    log_file_max_size_mb: int = 100
    log_file_retention_days: int = 90


@dataclass
class PDFConfig:
    """PDF processing configuration"""
    default_encryption_level: int = 128  # AES 128-bit
    default_permissions: int = -1  # All permissions for owner
    compress_output: bool = True
    preserve_metadata: bool = False  # Security: Remove metadata
    max_file_size_mb: int = 100
    allowed_extensions: list = field(default_factory=lambda: ['.pdf'])


@dataclass
class ExcelConfig:
    """Excel processing configuration"""
    default_worksheet_name: str = "Bank_Data"
    max_file_size_mb: int = 50
    allowed_extensions: list = field(default_factory=lambda: ['.xlsx', '.xls'])
    default_protection_options: Dict[str, bool] = field(default_factory=lambda: {
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


@dataclass
class ApplicationConfig:
    """Main application configuration"""
    app_name: str = "Bank Document Protection Tool"
    app_version: str = "1.0.0"
    app_author: str = "Bank IT Security Team"
    app_description: str = "Production-ready document protection for banking environments"
    
    # File paths
    log_directory: Path = field(default_factory=lambda: Path("logs"))
    output_directory: Path = field(default_factory=lambda: Path("protected_documents"))
    temp_directory: Path = field(default_factory=lambda: Path("temp"))
    
    # GUI settings
    gui_theme: str = "clam"
    gui_default_width: int = 800
    gui_default_height: int = 600
    gui_min_width: int = 600
    gui_min_height: int = 400
    
    # Security settings
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    # Processing settings
    pdf: PDFConfig = field(default_factory=PDFConfig)
    excel: ExcelConfig = field(default_factory=ExcelConfig)
    
    # Environment-specific settings
    environment: str = field(default_factory=lambda: os.getenv("BANK_DOC_ENV", "production"))
    debug_mode: bool = field(default_factory=lambda: os.getenv("BANK_DOC_DEBUG", "false").lower() == "true")
    
    def __post_init__(self):
        """Post-initialization setup"""
        # Create necessary directories
        self.log_directory.mkdir(exist_ok=True)
        self.output_directory.mkdir(exist_ok=True)
        self.temp_directory.mkdir(exist_ok=True)
        
        # Set appropriate permissions for directories
        if os.name == 'nt':  # Windows
            try:
                import stat
                os.chmod(self.log_directory, stat.S_IRWXU)  # Owner read/write/execute only
                os.chmod(self.output_directory, stat.S_IRWXU)
                os.chmod(self.temp_directory, stat.S_IRWXU)
            except:
                pass  # Ignore permission errors on Windows


class ConfigManager:
    """Manages application configuration and environment variables"""
    
    def __init__(self):
        self.config = ApplicationConfig()
        self._load_environment_variables()
    
    def _load_environment_variables(self):
        """Load configuration from environment variables"""
        # Security settings
        if min_pwd_len := os.getenv("BANK_DOC_MIN_PASSWORD_LENGTH"):
            try:
                self.config.security.min_password_length = int(min_pwd_len)
            except ValueError:
                pass
        
        if session_timeout := os.getenv("BANK_DOC_SESSION_TIMEOUT"):
            try:
                self.config.security.session_timeout_minutes = int(session_timeout)
            except ValueError:
                pass
        
        # File size limits
        if pdf_max_size := os.getenv("BANK_DOC_PDF_MAX_SIZE_MB"):
            try:
                self.config.pdf.max_file_size_mb = int(pdf_max_size)
            except ValueError:
                pass
        
        if excel_max_size := os.getenv("BANK_DOC_EXCEL_MAX_SIZE_MB"):
            try:
                self.config.excel.max_file_size_mb = int(excel_max_size)
            except ValueError:
                pass
        
        # Logging settings
        if log_retention := os.getenv("BANK_DOC_LOG_RETENTION_DAYS"):
            try:
                self.config.security.log_file_retention_days = int(log_retention)
            except ValueError:
                pass
        
        # Directory settings
        if log_dir := os.getenv("BANK_DOC_LOG_DIR"):
            self.config.log_directory = Path(log_dir)
        
        if output_dir := os.getenv("BANK_DOC_OUTPUT_DIR"):
            self.config.output_directory = Path(output_dir)
        
        # Audit logging
        if audit_logging := os.getenv("BANK_DOC_ENABLE_AUDIT"):
            self.config.security.enable_audit_logging = audit_logging.lower() == "true"
    
    def get_config(self) -> ApplicationConfig:
        """Get the current configuration"""
        return self.config
    
    def get_security_config(self) -> SecurityConfig:
        """Get security configuration"""
        return self.config.security
    
    def get_pdf_config(self) -> PDFConfig:
        """Get PDF configuration"""
        return self.config.pdf
    
    def get_excel_config(self) -> ExcelConfig:
        """Get Excel configuration"""
        return self.config.excel
    
    def validate_configuration(self) -> tuple[bool, str]:
        """Validate the current configuration"""
        errors = []
        
        # Validate security settings
        if self.config.security.min_password_length < 8:
            errors.append("Minimum password length must be at least 8 characters")
        
        if self.config.security.session_timeout_minutes < 1:
            errors.append("Session timeout must be at least 1 minute")
        
        # Validate file size limits
        if self.config.pdf.max_file_size_mb < 1:
            errors.append("PDF maximum file size must be at least 1 MB")
        
        if self.config.excel.max_file_size_mb < 1:
            errors.append("Excel maximum file size must be at least 1 MB")
        
        # Validate directories
        try:
            self.config.log_directory.mkdir(exist_ok=True)
            self.config.output_directory.mkdir(exist_ok=True)
            self.config.temp_directory.mkdir(exist_ok=True)
        except Exception as e:
            errors.append(f"Cannot create required directories: {e}")
        
        if errors:
            return False, "; ".join(errors)
        
        return True, "Configuration is valid"
    
    def get_environment_info(self) -> Dict[str, Any]:
        """Get environment information for troubleshooting"""
        return {
            "environment": self.config.environment,
            "debug_mode": self.config.debug_mode,
            "python_version": f"{os.sys.version_info.major}.{os.sys.version_info.minor}.{os.sys.version_info.micro}",
            "platform": os.name,
            "user": os.getenv("USERNAME", "Unknown"),
            "computer": os.getenv("COMPUTERNAME", "Unknown"),
            "working_directory": str(Path.cwd()),
            "log_directory": str(self.config.log_directory),
            "output_directory": str(self.config.output_directory),
            "temp_directory": str(self.config.temp_directory)
        }


# Global configuration instance
config_manager = ConfigManager()


def get_config() -> ApplicationConfig:
    """Get the global configuration instance"""
    return config_manager.get_config()


def get_security_config() -> SecurityConfig:
    """Get the global security configuration"""
    return config_manager.get_security_config()


def get_pdf_config() -> PDFConfig:
    """Get the global PDF configuration"""
    return config_manager.get_pdf_config()


def get_excel_config() -> ExcelConfig:
    """Get the global Excel configuration"""
    return config_manager.get_excel_config()


# Bank-specific configuration templates
BANK_PRODUCTION_CONFIG = {
    "BANK_DOC_ENV": "production",
    "BANK_DOC_DEBUG": "false",
    "BANK_DOC_MIN_PASSWORD_LENGTH": "12",
    "BANK_DOC_SESSION_TIMEOUT": "15",
    "BANK_DOC_PDF_MAX_SIZE_MB": "50",
    "BANK_DOC_EXCEL_MAX_SIZE_MB": "25",
    "BANK_DOC_LOG_RETENTION_DAYS": "180",
    "BANK_DOC_ENABLE_AUDIT": "true"
}

BANK_DEVELOPMENT_CONFIG = {
    "BANK_DOC_ENV": "development",
    "BANK_DOC_DEBUG": "true",
    "BANK_DOC_MIN_PASSWORD_LENGTH": "8",
    "BANK_DOC_SESSION_TIMEOUT": "60",
    "BANK_DOC_PDF_MAX_SIZE_MB": "100",
    "BANK_DOC_EXCEL_MAX_SIZE_MB": "50",
    "BANK_DOC_LOG_RETENTION_DAYS": "30",
    "BANK_DOC_ENABLE_AUDIT": "true"
}


def apply_bank_config(config_type: str = "production"):
    """Apply predefined bank configuration"""
    if config_type == "production":
        config_dict = BANK_PRODUCTION_CONFIG
    elif config_type == "development":
        config_dict = BANK_DEVELOPMENT_CONFIG
    else:
        raise ValueError(f"Unknown configuration type: {config_type}")
    
    for key, value in config_dict.items():
        os.environ[key] = value
    
    # Reload configuration
    global config_manager
    config_manager = ConfigManager()


if __name__ == "__main__":
    # Configuration validation and testing
    config = get_config()
    is_valid, message = config_manager.validate_configuration()
    
    print(f"Configuration Status: {'Valid' if is_valid else 'Invalid'}")
    print(f"Message: {message}")
    print(f"Environment: {config.environment}")
    print(f"Debug Mode: {config.debug_mode}")
    print(f"Log Directory: {config.log_directory}")
    print(f"Output Directory: {config.output_directory}")
    
    # Display environment info
    print("\nEnvironment Information:")
    for key, value in config_manager.get_environment_info().items():
        print(f"  {key}: {value}")