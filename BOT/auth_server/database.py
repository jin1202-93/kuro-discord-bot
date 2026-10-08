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
ONLINE_WINDOW_SECONDS = 90
LICENSE_TIERS = frozenset(("basic", "premium"))
MAX_NICKNAME_LENGTH = 32
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
LICENSE_ID_PATTERN = re.compile(r"[A-F0-9]{16}")


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
        _get_supabase_client().table("kuro_auth_codes_v2").select("code_hash").limit(0).execute()
        return

    with _connection() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS auth_codes (
                code_hash TEXT PRIMARY KEY,
                license_id TEXT NOT NULL,
                expires_at REAL,
                used INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS licenses (
                license_id TEXT PRIMARY KEY,
                device_id TEXT,
                active INTEGER NOT NULL DEFAULT 1,
                created_at REAL NOT NULL,
                last_seen_at REAL,
                tier TEXT NOT NULL DEFAULT 'basic',
                nickname TEXT
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                license_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                expires_at REAL
            );
            CREATE INDEX IF NOT EXISTS sessions_user_idx
                ON sessions(license_id);
            """
        )
        license_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(licenses)")
        }
        if "last_seen_at" not in license_columns:
            connection.execute("ALTER TABLE licenses ADD COLUMN last_seen_at REAL")
        if "tier" not in license_columns:
            connection.execute(
                "ALTER TABLE licenses ADD COLUMN tier TEXT NOT NULL DEFAULT 'basic'"
            )
        if "nickname" not in license_columns:
            connection.execute("ALTER TABLE licenses ADD COLUMN nickname TEXT")


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
    if "AUTH_LICENSE_NOT_FOUND" in message:
        raise ValueError("관리 ID를 찾을 수 없습니다. 발급 메시지의 ID를 확인하세요.") from error
    if "AUTH_LICENSE_REVOKED" in message:
        raise PermissionError("이미 취소된 인증입니다. 새 코드를 발급하세요.") from error
    raise error


def _execute(connection, query, parameters=()):
    return connection.execute(query, parameters)


def _begin_write(connection):
    connection.execute("BEGIN IMMEDIATE")


def _sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _new_code():
    characters = "".join(secrets.choice(CODE_ALPHABET) for _ in range(24))
    return "-".join(characters[index:index + 4] for index in range(0, 24, 4))


def _validate_license_id(license_id):
    normalized = str(license_id).strip().upper()
    if not LICENSE_ID_PATTERN.fullmatch(normalized):
        raise ValueError("관리 ID는 발급 메시지에 표시된 16자리 영문/숫자 값이어야 합니다.")
    return normalized


def _validate_tier(tier):
    normalized = str(tier).strip().lower()
    if normalized not in LICENSE_TIERS:
        raise ValueError("등급은 basic 또는 premium이어야 합니다.")
    return normalized


def _validate_nickname(nickname):
    if nickname is None:
        return None
    normalized = str(nickname).strip()
    if not normalized or len(normalized) > MAX_NICKNAME_LENGTH:
        raise ValueError(f"별명은 1~{MAX_NICKNAME_LENGTH}자로 입력하세요.")
    return normalized


def issue_code(expires_days=30, tier="basic", nickname=None):
    if not 0 <= expires_days <= 365:
        raise ValueError("코드 유효기간은 0(무제한)~365일이어야 합니다.")
    tier = _validate_tier(tier)
    nickname = _validate_nickname(nickname)

    code = _new_code()
    license_id = secrets.token_hex(8).upper()
    code_hash = _sha256(code)

    if _uses_supabase():
        try:
            _get_supabase_client().rpc(
                "issue_auth_code_v2",
                {
                    "p_license_id": license_id,
                    "p_code_hash": code_hash,
                    "p_expires_days": expires_days,
                    "p_tier": tier,
                    "p_nickname": nickname,
                },
            ).execute()
        except Exception as error:
            _supabase_error(error)
        return code, license_id

    now = time.time()
    with _connection() as connection:
        _begin_write(connection)
        _execute(
            connection,
            "INSERT INTO licenses(license_id, device_id, active, created_at, tier, nickname) "
            "VALUES (?, NULL, 1, ?, ?, ?)",
            (license_id, now, tier, nickname),
        )
        _execute(
            connection,
            "INSERT INTO auth_codes(code_hash, license_id, expires_at) "
            "VALUES (?, ?, ?)",
            (
                code_hash,
                license_id,
                None if expires_days == 0 else now + expires_days * 24 * 60 * 60,
            ),
        )
    return code, license_id


def redeem_code(code, device_id):
    code = code.strip().upper()
    if _uses_supabase():
        token = secrets.token_urlsafe(32)
        try:
            result = _get_supabase_client().rpc(
                "redeem_auth_code_v2",
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
            "SELECT license_id, expires_at, used FROM auth_codes "
            "WHERE code_hash = ?",
            (_sha256(code),),
        ).fetchone()
        if (
            auth_code is None
            or auth_code["used"]
            or (
                auth_code["expires_at"] is not None
                and auth_code["expires_at"] <= now
            )
        ):
            raise ValueError("서버에 등록되지 않았거나 이미 사용/만료된 코드입니다. 관리자에게 문의하세요.")

        license_row = _execute(
            connection,
            "SELECT device_id, active FROM licenses WHERE license_id = ?",
            (auth_code["license_id"],),
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
            "UPDATE licenses SET device_id = ? WHERE license_id = ?",
            (device_id, auth_code["license_id"]),
        )
        _execute(
            connection,
            "UPDATE auth_codes SET used = 1 WHERE code_hash = ?",
            (_sha256(code),),
        )
        _execute(
            connection,
            "INSERT INTO sessions(token_hash, license_id, device_id, expires_at) "
            "VALUES (?, ?, ?, ?)",
            (
                _sha256(token),
                auth_code["license_id"],
                device_id,
                (
                    None
                    if auth_code["expires_at"] is None
                    else now + SESSION_DAYS * 24 * 60 * 60
                ),
            ),
        )
    return token


def verify_session(token, device_id):
    if _uses_supabase():
        try:
            result = _get_supabase_client().rpc(
                "verify_auth_session_v2",
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
            SELECT sessions.license_id
            FROM sessions
            JOIN licenses USING(license_id)
            WHERE sessions.token_hash = ?
              AND sessions.device_id = ?
              AND (sessions.expires_at IS NULL OR sessions.expires_at > ?)
              AND licenses.device_id = ?
              AND licenses.active = 1
            """,
            (_sha256(token), device_id, now, device_id),
        ).fetchone()
        if session is not None:
            _execute(
                connection,
                "UPDATE licenses SET last_seen_at = ? WHERE license_id = ?",
                (now, session["license_id"]),
            )
    if session is None:
        return None
    return session["license_id"]


def get_license_status(license_id):
    license_id = _validate_license_id(license_id)
    if _uses_supabase():
        try:
            result = (
                _get_supabase_client()
                .table("kuro_auth_licenses_v2")
                .select("license_id,active,last_seen_at,tier,nickname")
                .eq("license_id", license_id)
                .limit(1)
                .execute()
            )
        except Exception as error:
            _supabase_error(error)
        rows = result.data or []
        if not rows:
            raise ValueError("관리 ID를 찾을 수 없습니다. 발급 메시지의 ID를 확인하세요.")
        row = rows[0]
        last_seen = row.get("last_seen_at")
        if isinstance(last_seen, str):
            from datetime import datetime

            last_seen = datetime.fromisoformat(
                last_seen.replace("Z", "+00:00")
            ).timestamp()
    else:
        with _connection() as connection:
            row = _execute(
                connection,
                "SELECT license_id, active, last_seen_at, tier, nickname FROM licenses WHERE license_id = ?",
                (license_id,),
            ).fetchone()
        if row is None:
            raise ValueError("관리 ID를 찾을 수 없습니다. 발급 메시지의 ID를 확인하세요.")
        last_seen = row["last_seen_at"]

    active = bool(row["active"])
    last_seen = float(last_seen) if last_seen is not None else None
    return {
        "license_id": license_id,
        "active": active,
        "last_seen_at": last_seen,
        "tier": _validate_tier(row["tier"]),
        "nickname": row["nickname"],
        "online": bool(
            active
            and last_seen is not None
            and time.time() - last_seen <= ONLINE_WINDOW_SECONDS
        ),
    }


def set_license_tier(license_id, tier):
    license_id = _validate_license_id(license_id)
    tier = _validate_tier(tier)
    if _uses_supabase():
        try:
            _get_supabase_client().table("kuro_auth_licenses_v2").update(
                {"tier": tier}
            ).eq("license_id", license_id).execute()
        except Exception as error:
            _supabase_error(error)
    else:
        with _connection() as connection:
            updated = _execute(
                connection,
                "UPDATE licenses SET tier = ? WHERE license_id = ?",
                (tier, license_id),
            )
        if updated.rowcount == 0:
            raise ValueError("관리 ID를 찾을 수 없습니다. 발급 메시지의 ID를 확인하세요.")
    return get_license_status(license_id)


def set_license_nickname(license_id, nickname):
    license_id = _validate_license_id(license_id)
    nickname = _validate_nickname(nickname)
    if nickname is None:
        raise ValueError(f"별명은 1~{MAX_NICKNAME_LENGTH}자로 입력하세요.")
    if _uses_supabase():
        try:
            _get_supabase_client().table("kuro_auth_licenses_v2").update(
                {"nickname": nickname}
            ).eq("license_id", license_id).execute()
        except Exception as error:
            _supabase_error(error)
    else:
        with _connection() as connection:
            updated = _execute(
                connection,
                "UPDATE licenses SET nickname = ? WHERE license_id = ?",
                (nickname, license_id),
            )
        if updated.rowcount == 0:
            raise ValueError("관리 ID를 찾을 수 없습니다. 발급 메시지의 ID를 확인하세요.")
    return get_license_status(license_id)


def reset_device(license_id, expires_days=30):
    license_id = _validate_license_id(license_id)
    if not 0 <= expires_days <= 365:
        raise ValueError("코드 유효기간은 0(무제한)~365일이어야 합니다.")
    code = _new_code()
    code_hash = _sha256(code)
    if _uses_supabase():
        try:
            _get_supabase_client().rpc(
                "reset_auth_device_v2",
                {
                    "p_license_id": license_id,
                    "p_code_hash": code_hash,
                    "p_expires_days": expires_days,
                },
            ).execute()
        except Exception as error:
            _supabase_error(error)
        return code

    with _connection() as connection:
        _begin_write(connection)
        license_row = _execute(
            connection,
            "SELECT active FROM licenses WHERE license_id = ?",
            (license_id,),
        ).fetchone()
        if license_row is None:
            raise ValueError("관리 ID를 찾을 수 없습니다. 발급 메시지의 ID를 확인하세요.")
        if not license_row["active"]:
            raise PermissionError("이미 취소된 인증입니다. 새 코드를 발급하세요.")
        _execute(
            connection,
            "UPDATE licenses SET device_id = NULL, last_seen_at = NULL WHERE license_id = ?",
            (license_id,),
        )
        _execute(
            connection,
            "DELETE FROM sessions WHERE license_id = ?",
            (license_id,),
        )
        _execute(
            connection,
            "DELETE FROM auth_codes WHERE license_id = ?",
            (license_id,),
        )
        _execute(
            connection,
            "INSERT INTO auth_codes(code_hash, license_id, expires_at) VALUES (?, ?, ?)",
            (
                code_hash,
                license_id,
                None if expires_days == 0 else time.time() + expires_days * 24 * 60 * 60,
            ),
        )
    return code


def revoke_user(license_id):
    license_id = _validate_license_id(license_id)
    if _uses_supabase():
        try:
            _get_supabase_client().rpc(
                "revoke_auth_user_v2",
                {"p_license_id": license_id},
            ).execute()
        except Exception as error:
            _supabase_error(error)
        return

    with _connection() as connection:
        _begin_write(connection)
        updated = _execute(
            connection,
            "UPDATE licenses SET active = 0 WHERE license_id = ?",
            (license_id,),
        )
        if updated.rowcount == 0:
            raise ValueError("관리 ID를 찾을 수 없습니다. 발급 메시지의 ID를 확인하세요.")
        _execute(
            connection,
            "DELETE FROM sessions WHERE license_id = ?",
            (license_id,),
        )
        _execute(
            connection,
            "DELETE FROM auth_codes WHERE license_id = ?",
            (license_id,),
        )
