"""
Structured logging setup using structlog.
"""

import logging
import sys
from pathlib import Path
from typing import Optional

import structlog


def configure_logging(
    log_level: str = "INFO",
    log_file: Optional[Path] = None,
) -> None:
    """Configure structured logging for the application."""
    
    log_level_upper = log_level.upper()
    
    # Configure standard library logging
    logging.basicConfig(
        level=getattr(logging, log_level_upper),
        format="%(message)s",
        stream=sys.stdout,
    )
    
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
            structlog.processors.JSONRenderer(),
        ],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(getattr(logging, log_level_upper))
        logging.getLogger().addHandler(file_handler)


def get_logger(name: str) -> structlog.typing.FilteringBoundLogger:
    """Get a logger instance."""
    return structlog.get_logger(name)
