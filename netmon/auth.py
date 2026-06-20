#!/usr/bin/env python3
"""
Модуль аутентификации.
SQLite база данных с пользователями, параметризованные запросы (защита от SQL injection).
"""
import hashlib
import os
import sqlite3
from pathlib import Path
from typing import Optional

# База данных будет рядом с api_server.py
DB_DIR = Path(__file__).resolve().parent.parent
DB_PATH = DB_DIR / "data" / "users.db"


def get_db() -> sqlite3.Connection:
    """Возвращает соединение с БД (создаёт директорию, если её нет)."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db() -> None:
    """Создаёт таблицу users и добавляет дефолтного пользователя, если таблица пуста."""
    conn = get_db()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT DEFAULT (datetime('now'))
            )
        """)
        conn.commit()

        # Проверяем, есть ли уже пользователи
        cursor = conn.execute("SELECT COUNT(*) as cnt FROM users")
        row = cursor.fetchone()
        if row["cnt"] == 0:
            username = "admin"
            password = "admin"
            # Хешируем пароль с солью: sha256(salt + password)
            salt = os.urandom(32).hex()
            password_hash = _hash_password(password, salt)
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash),
            )
            conn.commit()
    finally:
        conn.close()


def _hash_password(password: str, salt: Optional[str] = None) -> str:
    """Хеширует пароль: salt:sha256(salt+password)."""
    if salt is None:
        salt = os.urandom(32).hex()
    h = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{h}"


def verify_password(password: str, password_hash: str) -> bool:
    """Проверяет пароль против сохранённого хеша."""
    if ":" not in password_hash:
        return False
    salt, stored_hash = password_hash.split(":", 1)
    computed = hashlib.sha256((salt + password).encode()).hexdigest()
    return computed == stored_hash


def authenticate_user(username: str, password: str) -> Optional[dict]:
    """
    Аутентифицирует пользователя.
    Параметризованный запрос — защита от SQL injection.
    Возвращает dict с данными пользователя или None.
    """
    conn = get_db()
    try:
        cursor = conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        )
        row = cursor.fetchone()
        if row is None:
            return None

        if not verify_password(password, row["password_hash"]):
            return None

        return {"id": row["id"], "username": row["username"]}
    finally:
        conn.close()


def create_user(username: str, password: str) -> bool:
    """
    Создаёт нового пользователя (регистрация).
    Параметризованный запрос — защита от SQL injection.
    Возвращает True при успехе, False если пользователь уже существует.
    """
    conn = get_db()
    try:
        password_hash = _hash_password(password)
        conn.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()