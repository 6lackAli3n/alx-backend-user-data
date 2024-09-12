#!/usr/bin/env python3
"""
Module for filtering log data by obfuscating sensitive fields.
"""


import re
from typing import List

def filter_datum(fields: List[str], redaction: str, message: str, separator: str) -> str:
    """Returns the log message with specified fields obfuscated."""
    pattern = '|'.join([f'{field}=[^{separator}]*' for field in fields])
    return re.sub(pattern, lambda x: x.group(0).split('=')[0] + '=' + redaction, message)
