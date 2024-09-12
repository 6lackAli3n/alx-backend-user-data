#!/usr/bin/env python3
"""
Module for filtering log data by obfuscating sensitive fields.
"""


import logging
import re
from typing import List

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """Returns the log message with specified fields obfuscated."""
    pattern = '|'.join([f'{field}=[^{separator}]*' for field in fields])
    return re.sub(pattern, lambda x: x.group(0).split('=')[0] + '=' + redaction, message)


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class to obfuscate sensitive information."""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initialize the formatter with fields to redact."""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Filter sensitive data in the log record message."""
        original_message = super().format(record)
        return filter_datum(self.fields, self.REDACTION, original_message, self.SEPARATOR)

def get_logger() -> logging.Logger:
    """Creates and returns a logger named 'user_data'."""
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    # Create and configure StreamHandler with RedactingFormatter
    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(fields=PII_FIELDS)
    stream_handler.setFormatter(formatter)

    # Attach the handler to the logger
    logger.addHandler(stream_handler)

    return logger
