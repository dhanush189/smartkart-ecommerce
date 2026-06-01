import argparse
import os
import sqlite3
from decimal import Decimal
from datetime import datetime, date

import mysql.connector

from app import initialize_database


TABLES = [
    "admin",
    "users",
    "products",
    "addresses",
    "orders",
    "order_items",
    "super_admins",
]


def sqlite_columns(conn, table):
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    return [row[1] for row in rows]


def mysql_columns(cursor, table):
    cursor.execute(f"SHOW COLUMNS FROM {table}")
    return [row["Field"] for row in cursor.fetchall()]


def normalize_value(value):
    if value is None:
        return None

    if isinstance(value, bytes):
        return value.decode("utf-8")

    if isinstance(value, Decimal):
        return float(value)
        # Alternatively:
        # return str(value)

    if isinstance(value, (datetime, date)):
        return value.isoformat()

    return value


def copy_table(mysql_cursor, sqlite_conn, table):
    mysql_cols = mysql_columns(mysql_cursor, table)
    sqlite_cols = sqlite_columns(sqlite_conn, table)

    columns = [column for column in mysql_cols if column in sqlite_cols]

    if not columns:
        print(f"{table}: skipped, no matching columns")
        return

    column_list = ", ".join(columns)
    placeholders = ", ".join(["?"] * len(columns))

    mysql_cursor.execute(f"SELECT {column_list} FROM {table}")
    rows = mysql_cursor.fetchall()

    copied = 0

    for row in rows:
        try:
            values = [normalize_value(row[column]) for column in columns]

            sqlite_conn.execute(
                f"INSERT OR IGNORE INTO {table} ({column_list}) VALUES ({placeholders})",
                values,
            )

            copied += 1

        except Exception as e:
            print(f"Error copying row in {table}: {e}")
            print(f"Row data: {row}")

    sqlite_conn.commit()
    print(f"{table}: copied {copied} row(s)")


def main():
    parser = argparse.ArgumentParser(
        description="Copy SmartKart MySQL data into SQLite."
    )

    parser.add_argument(
        "--mysql-host",
        default=os.environ.get("MYSQL_HOST", "localhost")
    )

    parser.add_argument(
        "--mysql-user",
        default=os.environ.get("MYSQL_USER", "root")
    )

    parser.add_argument(
        "--mysql-password",
        default=os.environ.get("MYSQL_PASSWORD", "")
    )

    parser.add_argument(
        "--mysql-db",
        default=os.environ.get("MYSQL_DB", "smartcart_db")
    )

    parser.add_argument(
        "--sqlite-db",
        default=os.environ.get("SQLITE_DB", "smartkart.db")
    )

    args = parser.parse_args()

    print("Initializing SQLite database...")
    initialize_database()

    print("Connecting to MySQL...")
    mysql_conn = mysql.connector.connect(
        host=args.mysql_host,
        user=args.mysql_user,
        password=args.mysql_password,
        database=args.mysql_db,
    )

    mysql_cursor = mysql_conn.cursor(dictionary=True)

    print("Connecting to SQLite...")
    sqlite_conn = sqlite3.connect(args.sqlite_db)
    sqlite_conn.execute("PRAGMA foreign_keys = ON")

    try:
        for table in TABLES:
            print(f"\nMigrating table: {table}")
            copy_table(mysql_cursor, sqlite_conn, table)

        print("\nMigration completed successfully!")

    finally:
        mysql_cursor.close()
        mysql_conn.close()
        sqlite_conn.close()


if __name__ == "__main__":
    main()