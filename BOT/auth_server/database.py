import hashlib
import os
import re
from contextlib import contextmanager
from pathlib import Path
import secrets
import sqlite3
import time
from cryptography.fernet import Fernet, InvalidToken

DEFAULT_DATABASE = Path(__file__).resolve().parent / "auth.sqlite3"
SESSION_DAYS = 30
ONLINE_WINDOW_SECONDS = 90
LICENSE_TIERS = frozenset(("basic", "premium"))
MAX_NICKNAME_LENGTH = 32
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
LICENSE_ID_PATTERN = re.compile(r"[A-F0-9]{16}")
APP_VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+")
SHA256_PATTERN = re.compile(r"[A-Fa-f0-9]{64}")


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
    if os.environ.get("RENDER"):
        _code_cipher()
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
                used INTEGER NOT NULL DEFAULT 0,
                code_encrypted TEXT
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
            CREATE TABLE IF NOT EXISTS app_updates (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                version TEXT NOT NULL,
                minimum_version TEXT NOT NULL,
                download_url TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                release_notes TEXT NOT NULL DEFAULT '',
                updated_at REAL NOT NULL
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
        code_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(auth_codes)")
        }
        if "code_encrypted" not in code_columns:
            connection.execute("ALTER TABLE auth_codes ADD COLUMN code_encrypted TEXT")


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
    if "AUTH_NO_ACTIVE_SESSION" in message:
        raise ValueError("기한을 변경할 인증 세션이 없습니다. 해당 계정이 인증되었는지 확인하세요.") from error
    raise error


def _execute(connection, query, parameters=()):
    return connection.execute(query, parameters)


def _begin_write(connection):
    connection.execute("BEGIN IMMEDIATE")


def _sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _code_cipher():
    key = os.environ.get("CODE_ENCRYPTION_KEY", "").strip()
    if not key:
        raise RuntimeError("CODE_ENCRYPTION_KEY를 서버 환경변수에 설정하세요.")
    try:
        return Fernet(key.encode("ascii"))
    except (ValueError, UnicodeError) as error:
        raise RuntimeError("CODE_ENCRYPTION_KEY가 올바른 Fernet 키가 아닙니다.") from error


def _encrypt_code(code):
    return _code_cipher().encrypt(code.encode("ascii")).decode("ascii")


def _decrypt_code(encrypted_code):
    try:
        return _code_cipher().decrypt(encrypted_code.encode("ascii")).decode("ascii")
    except (InvalidToken, UnicodeError) as error:
        raise RuntimeError(
            "암호화 키가 변경되었거나 저장된 코드를 복호화할 수 없습니다."
        ) from error


def _new_code():
    characters = "".join(secrets.choice(CODE_ALPHABET) for _ in range(24))
    return "-".join(characters[index:index + 4] for index in range(0, 24, 4))


def _validate_license_id(license_id):
    normalized = str(license_id).strip().upper()
    if not LICENSE_ID_PATTERN.fullmatch(normalized):
        raise ValueError("관리 ID는 발급 메시지에 표시된 16자리 영문/숫자 값이어야 합니다.")
    return normalized


def resolve_license_id(license_id_or_nickname):
    lookup = str(license_id_or_nickname).strip()
    if LICENSE_ID_PATTERN.fullmatch(lookup.upper()):
        return lookup.upper()
    if not lookup or len(lookup) > MAX_NICKNAME_LENGTH:
        raise ValueError("관리 ID 또는 등록된 별명을 입력하세요.")

    if _uses_supabase():
        try:
            rows = (
                _get_supabase_client()
                .table("kuro_auth_licenses_v2")
                .select("license_id")
                .eq("nickname", lookup)
                .limit(2)
                .execute()
                .data
                or []
            )
        except Exception as error:
            _supabase_error(error)
    else:
        with _connection() as connection:
            rows = _execute(
                connection,
                "SELECT license_id FROM licenses WHERE nickname = ? LIMIT 2",
                (lookup,),
            ).fetchall()

    if len(rows) > 1:
        raise ValueError("같은 별명을 가진 계정이 여러 개입니다. 관리 ID를 입력하세요.")
    if not rows:
        raise ValueError("관리 ID 또는 별명을 찾을 수 없습니다.")
    return rows[0]["license_id"]


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
    code_encrypted = _encrypt_code(code)

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
                    "p_code_encrypted": code_encrypted,
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
            "INSERT INTO auth_codes(code_hash, license_id, expires_at, code_encrypted) "
            "VALUES (?, ?, ?, ?)",
            (
                code_hash,
                license_id,
                None if expires_days == 0 else now + expires_days * 24 * 60 * 60,
                code_encrypted,
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
            "UPDATE auth_codes SET used = 1, code_encrypted = NULL WHERE code_hash = ?",
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
    license_id = resolve_license_id(license_id)
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
    license_id = resolve_license_id(license_id)
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
    license_id = resolve_license_id(license_id)
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


def get_pending_code(license_id_or_nickname):
    query = str(license_id_or_nickname).strip()
    if not query:
        raise ValueError("관리 ID 또는 등록된 별명을 입력하세요.")

    if _uses_supabase():
        try:
            licenses = _get_supabase_client().table("kuro_auth_licenses_v2").select(
                "license_id,active,tier,nickname"
            )
            if LICENSE_ID_PATTERN.fullmatch(query.upper()):
                licenses = licenses.eq("license_id", query.upper())
            else:
                licenses = licenses.eq("nickname", query).limit(2)
            license_rows = licenses.execute().data or []
            if len(license_rows) > 1:
                raise ValueError("같은 별명을 가진 계정이 여러 개입니다. 관리 ID로 조회하세요.")
            if not license_rows:
                raise ValueError("관리 ID 또는 별명을 찾을 수 없습니다.")
            license_row = license_rows[0]
            code_rows = (
                _get_supabase_client()
                .table("kuro_auth_codes_v2")
                .select("code_encrypted,expires_at")
                .eq("license_id", license_row["license_id"])
                .eq("used", False)
                .limit(1)
                .execute()
                .data
                or []
            )
        except ValueError:
            raise
        except Exception as error:
            _supabase_error(error)
    else:
        with _connection() as connection:
            if LICENSE_ID_PATTERN.fullmatch(query.upper()):
                license_rows = _execute(
                    connection,
                    "SELECT license_id, active, tier, nickname FROM licenses "
                    "WHERE license_id = ?",
                    (query.upper(),),
                ).fetchall()
            else:
                license_rows = _execute(
                    connection,
                    "SELECT license_id, active, tier, nickname FROM licenses "
                    "WHERE nickname = ? LIMIT 2",
                    (query,),
                ).fetchall()
            if len(license_rows) > 1:
                raise ValueError("같은 별명을 가진 계정이 여러 개입니다. 관리 ID로 조회하세요.")
            if not license_rows:
                raise ValueError("관리 ID 또는 별명을 찾을 수 없습니다.")
            license_row = license_rows[0]
            code_rows = _execute(
                connection,
                "SELECT code_encrypted, expires_at FROM auth_codes "
                "WHERE license_id = ? AND used = 0 LIMIT 1",
                (license_row["license_id"],),
            ).fetchall()

    if not license_row["active"]:
        raise ValueError("인증이 취소된 계정입니다.")
    if not code_rows:
        raise ValueError("사용 가능한 미사용 코드가 없습니다. /resetdevice로 새 코드를 발급하세요.")
    code_row = code_rows[0]
    if not code_row["code_encrypted"]:
        raise ValueError("기존 코드는 암호화 저장 전 발급되어 조회할 수 없습니다. /resetdevice로 재발급하세요.")
    expires_at = code_row["expires_at"]
    if isinstance(expires_at, str):
        from datetime import datetime

        expires_at = datetime.fromisoformat(
            expires_at.replace("Z", "+00:00")
        ).timestamp()
    if expires_at is not None and float(expires_at) <= time.time():
        raise ValueError("코드가 만료되었습니다. /resetdevice로 새 코드를 발급하세요.")
    return {
        "license_id": license_row["license_id"],
        "nickname": license_row["nickname"],
        "tier": _validate_tier(license_row["tier"]),
        "code": _decrypt_code(code_row["code_encrypted"]),
    }


def _validate_app_version(version):
    normalized = str(version).strip()
    if not APP_VERSION_PATTERN.fullmatch(normalized):
        raise ValueError("버전은 major.minor.patch 형식으로 입력하세요. 예: 1.2.3")
    return tuple(int(part) for part in normalized.split("."))


def set_app_update(version, minimum_version, download_url, sha256, release_notes=""):
    version_key = _validate_app_version(version)
    minimum_key = _validate_app_version(minimum_version)
    version = str(version).strip()
    minimum_version = str(minimum_version).strip()
    download_url = str(download_url).strip()
    sha256 = str(sha256).strip().lower()
    release_notes = str(release_notes).strip()
    if minimum_key > version_key:
        raise ValueError("강제 적용 버전은 최신 버전보다 높을 수 없습니다.")
    if not download_url.startswith("https://") or len(download_url) > 2048:
        raise ValueError("다운로드 주소는 HTTPS URL이어야 합니다.")
    if not SHA256_PATTERN.fullmatch(sha256):
        raise ValueError("SHA-256은 64자리 16진수여야 합니다.")
    if len(release_notes) > 500:
        raise ValueError("업데이트 안내는 500자 이내로 입력하세요.")

    values = {
        "version": version,
        "minimum_version": minimum_version,
        "download_url": download_url,
        "sha256": sha256,
        "release_notes": release_notes,
    }
    if _uses_supabase():
        try:
            _get_supabase_client().table("kuro_auth_app_updates_v2").upsert(
                {"id": 1, **values}, on_conflict="id"
            ).execute()
        except Exception as error:
            _supabase_error(error)
    else:
        with _connection() as connection:
            _execute(
                connection,
                "INSERT INTO app_updates "
                "(id, version, minimum_version, download_url, sha256, release_notes, updated_at) "
                "VALUES (1, ?, ?, ?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET version=excluded.version, "
                "minimum_version=excluded.minimum_version, download_url=excluded.download_url, "
                "sha256=excluded.sha256, release_notes=excluded.release_notes, "
                "updated_at=excluded.updated_at",
                (
                    version,
                    minimum_version,
                    download_url,
                    sha256,
                    release_notes,
                    time.time(),
                ),
            )
    return get_app_update()


def get_app_update():
    if _uses_supabase():
        try:
            result = (
                _get_supabase_client()
                .table("kuro_auth_app_updates_v2")
                .select("version,minimum_version,download_url,sha256,release_notes")
                .eq("id", 1)
                .limit(1)
                .execute()
            )
        except Exception as error:
            _supabase_error(error)
        rows = result.data or []
        return rows[0] if rows else None

    with _connection() as connection:
        row = _execute(
            connection,
            "SELECT version, minimum_version, download_url, sha256, release_notes "
            "FROM app_updates WHERE id = 1",
        ).fetchone()
    return dict(row) if row is not None else None


def clear_app_update():
    if _uses_supabase():
        try:
            _get_supabase_client().table("kuro_auth_app_updates_v2").delete().eq(
                "id", 1
            ).execute()
        except Exception as error:
            _supabase_error(error)
        return
    with _connection() as connection:
        _execute(connection, "DELETE FROM app_updates WHERE id = 1")


def reset_device(license_id, expires_days=30):
    license_id = resolve_license_id(license_id)
    if not 0 <= expires_days <= 365:
        raise ValueError("코드 유효기간은 0(무제한)~365일이어야 합니다.")
    code = _new_code()
    code_hash = _sha256(code)
    code_encrypted = _encrypt_code(code)
    if _uses_supabase():
        try:
            _get_supabase_client().rpc(
                "reset_auth_device_v2",
                {
                    "p_license_id": license_id,
                    "p_code_hash": code_hash,
                    "p_expires_days": expires_days,
                    "p_code_encrypted": code_encrypted,
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
            "INSERT INTO auth_codes(code_hash, license_id, expires_at, code_encrypted) "
            "VALUES (?, ?, ?, ?)",
            (
                code_hash,
                license_id,
                None if expires_days == 0 else time.time() + expires_days * 24 * 60 * 60,
                code_encrypted,
            ),
        )
    return code


def set_license_session_expiry(license_id_or_nickname, expires_days):
    if not 0 <= expires_days <= 365:
        raise ValueError("이용 기한은 0(무제한)~365일이어야 합니다.")
    license_id = resolve_license_id(license_id_or_nickname)
    expires_at = (
        None if expires_days == 0 else time.time() + expires_days * 24 * 60 * 60
    )

    if _uses_supabase():
        try:
            _get_supabase_client().rpc(
                "set_auth_session_expiry_v2",
                {
                    "p_license_id": license_id,
                    "p_expires_days": expires_days,
                },
            ).execute()
        except Exception as error:
            _supabase_error(error)
        return license_id

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
            raise PermissionError("인증이 취소된 계정입니다.")
        updated = _execute(
            connection,
            "UPDATE sessions SET expires_at = ? WHERE license_id = ?",
            (expires_at, license_id),
        )
        if updated.rowcount == 0:
            raise ValueError("기한을 변경할 인증 세션이 없습니다. 해당 계정이 인증되었는지 확인하세요.")
    return license_id


def revoke_user(license_id):
    license_id = resolve_license_id(license_id)
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
