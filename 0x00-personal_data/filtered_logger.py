#!/usr/bin/env python3
"""
Module for filtering log data by obfuscating sensitive fields.
"""


import os
import mysql.connector
from mysql.connector import connection
import logging
import re
from typing import List
from datetime import datetime


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(
        fields: List[str], redaction:
        str, message: str, separator: str) -> str:
    """Returns the log message with specified fields obfuscated.
    """
    pattern = '|'.join([f'{field}=[^{separator}]*' for field in fields])
    return re.sub(pattern, lambda x: x.group(0).split(
        '=')[0] + '=' + redaction, message)


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class to obfuscate sensitive information.
    """
    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s"
    "%(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Initialize the formatter with fields to redact."""
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Filter sensitive data in the log record message."""
        original_message = super().format(record)
        return filter_datum(
                self.fields, self.REDACTION, original_message, self.SEPARATOR)


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


def get_db() -> connection.MySQLConnection:
    """
    Connects to a secure database and
    returns a MySQLConnection object.
    """
    # Retrieve environment variables with defaults where applicable
    db_user = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    db_password = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    db_host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    db_name = os.getenv('PERSONAL_DATA_DB_NAME')

    # Ensure that the database name is provided
    if not db_name:
        raise Exception(
                "Environment variable PERSONAL_DATA_DB_NAME must be set.")

    # Establish and return the database connection
    return mysql.connector.connect(
            user=db_user,
            password=db_password,
            host=db_host,
            database=db_name
            )


def filter_data(row):
    """
    Masks sensitive data by replacing it with '***'.
    """
    filtered = {
            'name': '***',
            'email': '***',
            'phone': '***',
            'ssn': '***',
            'password': '***',
            'ip': row[5],
            'last_login': row[6],
            'user_agent': row[7]
            }
    return filtered


def main():
    """
    Logs the information about user records in a table.
    """
    db = get_db()
    cursor = db.cursor()

    # Execute query to retrieve all rows from the users table
    cursor.execute(
            "SELECT name, email, phone, ssn, password,"
            "ip, last_login, user_agent FROM users;")

    # Set up logging format
    logging.basicConfig(
            format='[HOLBERTON]'
            'user_data INFO %(asctime)s: %(message)s', level=logging.INFO)

    # Fetch and process each row
    for row in cursor:
        filtered_row = filter_data(row)
        log_message = (
                f"name={filtered_row['name']}; email={filtered_row['email']}; "
                f"phone={filtered_row['phone']}; ssn={filtered_row['ssn']}; "
                f"password={filtered_row['password']};"
                f"ip={filtered_row['ip']}; "
                f"last_login={filtered_row['last_login']};"
                f"user_agent={filtered_row['user_agent']};")
        logging.info(log_message)

        # Close cursor and database connection
        cursor.close()
        db.close()


if __name__ == "__main__":
    main()
