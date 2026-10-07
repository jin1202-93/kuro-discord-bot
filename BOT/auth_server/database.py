import hashlib
import os
import re
from contextlib import contextmanager
from pathlib import Path
import secrets
import sqlite3
import time

DEFAULT_DATABASE = Path(__file__).resolve().parent / "auth.sqlite3"
SESSION_DAYS = 30


def _database_path():
    configured = os.environ.get("AUTH_DB_PATH")
    return Path(configured) if configured else DEFAULT_DATABASE


def _uses_supabase():
    url = os.environ.get("SUPABASE_URL", "").strip()
    key = os.environ.get("SUPABASE_KEY", "").strip()
    if bool(url) != bool(key):
        raise RuntimeError("SUPABASE_URL과 SUPABASE_KEY를 모두 설정해야 합니다.")
    if os.environ.get("RENDER") and not url:
        raise RuntimeError("Render 배포에는 SUPABASE_URL과 SUPABASE_KEY가 필요합니다.")
    return bool(url)


_supabase_client = None


def _get_supabase_client():
    global _supabase_client
    if _supabase_client is None:
        from supabase import create_client

        _supabase_client = create_client(
            os.environ["SUPABASE_URL"],
            os.environ["SUPABASE_KEY"],
        )
    return _supabase_client


def _connect():
    path = _database_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


@contextmanager
def _connection():
    connection = _connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database():
    if _uses_supabase():
        _get_supabase_client().table("kuro_auth_codes").select("code_hash").limit(0).execute()
        return

    with _connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS auth_codes (
                code_hash TEXT PRIMARY KEY,
                discord_user_id TEXT NOT NULL,
                expires_at REAL NOT NULL,
                used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS licenses (
                discord_user_id TEXT PRIMARY KEY,
                device_id TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                discord_user_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                expires_at REAL NOT NULL
            );
            CREATE INDEX IF NOT EXISTS sessions_user_idx
                ON sessions(discord_user_id);
            """
        )


def _supabase_error(error):
    message = str(error)
    if "AUTH_INVALID_CODE" in message:
        raise ValueError("서버에 등록되지 않았거나 이미 사용/만료된 코드입니다. 관리자에게 문의하세요.") from error
    if "AUTH_DEVICE_MISMATCH" in message:
        raise PermissionError("이 인증 코드는 이미 다른 PC에 연결된 계정입니다. 관리자에게 PC 초기화를 요청하세요.") from error
    if "AUTH_REVOKED" in message:
        raise PermissionError("이 계정의 프로그램 사용 권한이 비활성화되었습니다.") from error
    if "AUTH_CODE_DUPLICATE" in message:
        raise ValueError("이미 등록된 코드입니다. 다른 코드를 사용하세요.") from error
    raise error


def _execute(connection, query, parameters=()):
    return connection.execute(query, parameters)


def _begin_write(connection):
    connection.execute("BEGIN IMMEDIATE")


def _sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def register_code(discord_user_id, code, expires_days=30):
    code = code.strip().upper()
    if not re.fullmatch(r"[A-Z0-9-]{16,64}", code):
        raise ValueError("코드는 영문 대문자·숫자·하이픈으로 16~64자 입력하세요.")
    if not 1 <= expires_days <= 365:
        raise ValueError("코드 유효기간은 1~365일이어야 합니다.")

    if _uses_supabase():
        try:
            _get_supabase_client().rpc(
                "register_auth_code",
                {
                    "p_discord_user_id": str(discord_user_id),
                    "p_code_hash": _sha256(code),
                    "p_expires_days": expires_days,
                },
            ).execute()
        except Exception as error:
            _supabase_error(error)
        return

    now = time.time()
    with _connection() as connection:
        _begin_write(connection)
        code_hash = _sha256(code)
        existing_code = _execute(
            connection,
            "SELECT discord_user_id FROM auth_codes WHERE code_hash = ?",
            (code_hash,),
        ).fetchone()
        if existing_code is not None:
            raise ValueError("이미 등록된 코드입니다. 다른 코드를 사용하세요.")
        _execute(
            connection,
            "DELETE FROM auth_codes WHERE discord_user_id = ? AND used = 0",
            (str(discord_user_id),),
        )
        _execute(
            connection,
            "INSERT INTO auth_codes(code_hash, discord_user_id, expires_at) "
            "VALUES (?, ?, ?)",
            (code_hash, str(discord_user_id), now + expires_days * 24 * 60 * 60),
        )


def redeem_code(code, device_id):
    code = code.strip().upper()
    if _uses_supabase():
        token = secrets.token_urlsafe(32)
        try:
            result = _get_supabase_client().rpc(
                "redeem_auth_code",
                {
                    "p_code_hash": _sha256(code),
                    "p_device_id": device_id,
                    "p_token_hash": _sha256(token),
                },
            ).execute()
        except Exception as error:
            _supabase_error(error)
        return token

    now = time.time()
    token = secrets.token_urlsafe(32)
    with _connection() as connection:
        _begin_write(connection)
        auth_code = _execute(
            connection,
            "SELECT discord_user_id, expires_at, used FROM auth_codes "
            "WHERE code_hash = ?",
            (_sha256(code),),
        ).fetchone()
        if auth_code is None or auth_code["used"] or auth_code["expires_at"] <= now:
            raise ValueError("서버에 등록되지 않았거나 이미 사용/만료된 코드입니다. 관리자에게 문의하세요.")

        license_row = _execute(
            connection,
            "SELECT device_id, active FROM licenses WHERE discord_user_id = ?",
            (auth_code["discord_user_id"],),
        ).fetchone()
        if license_row is not None and not license_row["active"]:
            raise PermissionError("이 계정의 프로그램 사용 권한이 비활성화되었습니다.")
        if (
            license_row is not None
            and license_row["device_id"] is not None
            and license_row["device_id"] != device_id
        ):
            raise PermissionError(
                "이 인증 코드는 이미 다른 PC에 연결된 계정입니다. 관리자에게 PC 초기화를 요청하세요."
            )

        _execute(
            connection,
            "INSERT INTO licenses(discord_user_id, device_id, active, created_at) "
            "VALUES (?, ?, 1, ?) "
            "ON CONFLICT(discord_user_id) DO UPDATE SET device_id = excluded.device_id",
            (auth_code["discord_user_id"], device_id, now),
        )
        _execute(
            connection,
            "UPDATE auth_codes SET used = 1 WHERE code_hash = ?",
            (_sha256(code),),
        )
        _execute(
            connection,
            "INSERT INTO sessions(token_hash, discord_user_id, device_id, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (
                _sha256(token),
                auth_code["discord_user_id"],
                device_id,
                now + SESSION_DAYS * 24 * 60 * 60,
            ),
        )
    return token


def verify_session(token, device_id):
    if _uses_supabase():
        try:
            result = _get_supabase_client().rpc(
                "verify_auth_session",
                {
                    "p_token_hash": _sha256(token),
                    "p_device_id": device_id,
                },
            ).execute()
        except Exception as error:
            _supabase_error(error)
        data = result.data
        if isinstance(data, list):
            data = data[0] if data else None
        return data or None

    now = time.time()
    with _connection() as connection:
        session = _execute(
            connection,
            """
            SELECT sessions.discord_user_id
            FROM sessions
            JOIN licenses USING(discord_user_id)
            WHERE sessions.token_hash = ?
              AND sessions.device_id = ?
              AND sessions.expires_at > ?
              AND licenses.device_id = ?
              AND licenses.active = 1
            """,
            (_sha256(token), device_id, now, device_id),
        ).fetchone()
    if session is None:
        return None
    return session["discord_user_id"]


def reset_device(discord_user_id):
    if _uses_supabase():
        try:
            _get_supabase_client().rpc(
                "reset_auth_device",
                {"p_discord_user_id": str(discord_user_id)},
            ).execute()
        except Exception as error:
            _supabase_error(error)
        return

    with _connection() as connection:
        _begin_write(connection)
        _execute(
            connection,
            "UPDATE licenses SET device_id = NULL WHERE discord_user_id = ?",
            (str(discord_user_id),),
        )
        _execute(
            connection,
            "DELETE FROM sessions WHERE discord_user_id = ?",
            (str(discord_user_id),),
        )
        _execute(
            connection,
            "DELETE FROM auth_codes WHERE discord_user_id = ?",
            (str(discord_user_id),),
        )


def revoke_user(discord_user_id):
    if _uses_supabase():
        try:
            _get_supabase_client().rpc(
                "revoke_auth_user",
                {"p_discord_user_id": str(discord_user_id)},
            ).execute()
        except Exception as error:
            _supabase_error(error)
        return

    with _connection() as connection:
        _begin_write(connection)
        _execute(
            connection,
            "INSERT INTO licenses(discord_user_id, device_id, active, created_at) "
            "VALUES (?, NULL, 0, ?) "
            "ON CONFLICT(discord_user_id) DO UPDATE SET active = 0",
            (str(discord_user_id), time.time()),
        )
        _execute(
            connection,
            "DELETE FROM sessions WHERE discord_user_id = ?",
            (str(discord_user_id),),
        )
        _execute(
            connection,
            "DELETE FROM auth_codes WHERE discord_user_id = ?",
            (str(discord_user_id),),
        )
