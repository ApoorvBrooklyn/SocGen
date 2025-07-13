"""
Logging configuration for Security Management Platform
"""
import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Dict, Any
import structlog
from .config import settings


def setup_logging() -> None:
    """Setup structured logging configuration"""
    
    # Create logs directory if it doesn't exist
    logs_dir = Path(settings.LOGS_DIR)
    logs_dir.mkdir(exist_ok=True)
    
    # Configure standard logging
    log_level = getattr(logging, settings.LOG_LEVEL.upper())
    
    # Create formatters
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        logs_dir / "security_platform.log",
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(file_formatter)
    
    # Error file handler
    error_handler = logging.handlers.RotatingFileHandler(
        logs_dir / "errors.log",
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(error_handler)
    
    # Configure structlog
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer()
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.BoundLogger:
    """Get a structured logger instance"""
    return structlog.get_logger(name)


# Security-specific logging functions
def log_security_event(event_type: str, details: Dict[str, Any], severity: str = "info") -> None:
    """Log security-related events"""
    logger = get_logger("security")
    
    log_data = {
        "event_type": event_type,
        "severity": severity,
        "details": details,
        "component": "security_platform"
    }
    
    if severity == "critical":
        logger.critical("Security event", **log_data)
    elif severity == "error":
        logger.error("Security event", **log_data)
    elif severity == "warning":
        logger.warning("Security event", **log_data)
    else:
        logger.info("Security event", **log_data)


def log_vulnerability_event(cve_id: str, action: str, details: Dict[str, Any]) -> None:
    """Log vulnerability-related events"""
    logger = get_logger("vulnerability")
    
    logger.info(
        "Vulnerability event",
        cve_id=cve_id,
        action=action,
        details=details,
        component="vulnerability_management"
    )


def log_llm_interaction(prompt: str, response: str, model: str, processing_time: float) -> None:
    """Log LLM interactions for monitoring and debugging"""
    logger = get_logger("llm")
    
    logger.info(
        "LLM interaction",
        model=model,
        prompt_length=len(prompt),
        response_length=len(response),
        processing_time=processing_time,
        component="llm_service"
    )


def log_scan_event(scan_id: str, scan_type: str, target: str, status: str, details: Dict[str, Any] = None) -> None:
    """Log vulnerability scan events"""
    logger = get_logger("scanner")
    
    logger.info(
        "Scan event",
        scan_id=scan_id,
        scan_type=scan_type,
        target=target,
        status=status,
        details=details or {},
        component="vulnerability_scanner"
    ) 