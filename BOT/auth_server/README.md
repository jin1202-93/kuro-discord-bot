# KURO HELPER Discord 인증 서버

이 서버는 Discord 봇과 HTTPS 인증 API를 한 프로세스에서 실행합니다. 인증 코드는 SHA-256 해시와 서버 비밀키로 암호화한 값으로 저장합니다. Discord bot token, Supabase service-role key, `CODE_ENCRYPTION_KEY`는 Render 환경변수에만 저장하고 클라이언트 EXE나 GitHub에는 넣지 않습니다.

## 인증 흐름

1. 관리자가 `/issuecode`에서 기본/프리미엄 등급과 선택 별명을 지정하면 코드가 발급됩니다. 기본 유효기간은 30일이며 `expires_days`에 `365`를 넣으면 365일, `0`을 넣으면 만료되지 않습니다.
2. 봇은 무작위 코드와 관리 ID를 관리자에게만 보여줍니다. 코드는 테스터에게 전달하고 관리 ID는 초기화/취소를 위해 보관하세요. DB에는 코드 원문 대신 SHA-256 해시와 암호문을 저장합니다. 암호화 키를 잃거나 바꾸면 미사용 코드 원문을 복구할 수 없습니다.
3. 코드는 한 번만 사용할 수 있습니다. 테스터가 입력하면 관리 ID가 PC 한 대에 연결됩니다. 기간이 있는 코드는 인증 세션이 30일 유효하고, 무제한 코드는 관리자가 취소할 때까지 세션도 만료되지 않습니다.
4. 앱은 실행 중 30초마다 서버에 세션을 확인합니다. 관리자가 취소하면 다음 확인에서 매크로를 멈추고 앱을 종료합니다. PC가 오프라인이면 재접속 후 취소를 확인합니다.
5. `/resetdevice`, `/revokeuser`, `/checkuser`, `/settier`, `/setnickname`, `/getcode`는 관리 ID 또는 등록된 별명을 받습니다. 별명은 정확히 일치해야 하며, 중복된 별명은 잘못된 계정 조작을 막기 위해 관리 ID를 요구합니다.
6. 관리자는 `/resetdevice 관리ID또는별명 [유효기간]`으로 기기를 초기화하고 같은 관리 ID에 새 코드를 발급할 수 있습니다.
7. 관리자는 `/revokeuser 관리ID또는별명`으로 권한을 취소할 수 있습니다. 실행 중인 앱은 늦어도 다음 온라인 확인에서 종료됩니다.
8. 관리자는 `/checkuser 관리ID또는별명`으로 최근 접속 상태를 확인할 수 있습니다. 유효한 세션 확인이 있을 때 `last_seen_at`이 갱신되고, 최근 90초 이내면 온라인으로 표시됩니다. 앱 종료나 네트워크 단절은 확인 요청이 끊긴 뒤 90초가 지나야 오프라인으로 표시됩니다.
9. 관리자는 `/settier 관리ID또는별명 등급`으로 기존 인증 등급을 바꾸고, `/setnickname 관리ID또는별명 별명`으로 별명을 등록/수정할 수 있습니다. 변경된 등급은 실행 중인 앱의 다음 인증 확인 때 감지되어 앱을 다시 실행한 뒤 적용됩니다.
10. 관리자는 `/getcode 관리ID또는별명`으로 미사용 코드를 비공개 조회할 수 있습니다. 이미 사용/만료된 코드나 암호화 저장 기능 배포 전에 발급된 코드는 조회되지 않습니다. 후자는 `/resetdevice`로 재발급하세요.
11. 새 업데이트 ZIP은 HTTPS 주소와 SHA-256을 준비해 `/setappupdate`에 등록합니다. `minimum_version`을 `0.0.0`으로 두면 앱 실행 때 안내 후 사용자가 선택하고, 배포 버전과 같은 값으로 지정하면 그보다 낮은 버전은 필수 업데이트 대상입니다. `/clearappupdate`로 정책을 해제할 수 있습니다.

기본 등급은 자동사냥과 일반 보스 이동 등 나머지 기능을 사용할 수 있지만, 다캐릭 보스돌이, 캐릭터 순환, 레벨별 사냥터 자동 이동, 정기 등록은 사용할 수 없습니다. 프리미엄은 전체 기능을 사용할 수 있습니다.

## Discord 설정

1. Discord Developer Portal에서 새 Application을 만들고 Bot을 추가합니다.
2. Bot token을 발급합니다. 토큰은 이 저장소에 입력하거나 EXE에 포함하지 마세요.
3. 봇을 관리용 Discord 서버에 초대합니다. `bot`과 `applications.commands` scope를 선택합니다. 테스터는 서버에 초대할 필요가 없습니다.
4. 서버 설정에서 `인증 관리자` 역할을 만들고 코드 발급/초기화/취소를 할 관리자에게 부여합니다.
5. Developer Mode를 켜고 서버 ID 및 관리자 역할 ID를 복사합니다.

## Supabase 테스트 DB 설정

1. Supabase 프로젝트의 SQL Editor를 엽니다.
2. `BOT/auth_server/supabase_schema.sql` 최신 내용을 실행합니다. 기존 테이블은 그대로 두고 v2 테이블과 RPC를 갱신합니다. 이미 서비스 중인 계정은 기본 등급으로 설정되며, 만료·최근 접속·별명·암호화 코드 컬럼과 앱 업데이트 테이블도 갱신됩니다.
3. Project URL과 `service_role` 키를 보관합니다. 이 키는 서버 전용 비밀 값이며 클라이언트 앱이나 GitHub에 올리면 안 됩니다.

인증 코드를 실제로 한 번만 사용할 수 있도록 DB 트랜잭션을 적용합니다. 등록, 인증, 기기 초기화, 권한 취소는 SQL RPC 함수로 실행됩니다.

## Render 테스트 서버 설정

저장소 루트의 `render.yaml`은 Render 무료 테스트 서비스를 구성합니다. 봇과 API는 한 프로세스에서 실행되므로 개인 PC를 켜둘 필요가 없습니다.

GitHub 저장소를 Render Blueprint로 연결한 다음 다음 환경변수를 입력합니다.

- `DISCORD_BOT_TOKEN`: Developer Portal에서 발급한 비밀 토큰
- `DISCORD_GUILD_ID`: 인증에 사용할 Discord 서버 ID
- `DISCORD_ADMIN_ROLE_ID`: 코드 등록, PC 초기화, 권한 취소를 할 관리자 역할 ID
- `SUPABASE_URL`: Supabase Project URL
- `SUPABASE_KEY`: Supabase `service_role` 키
- `CODE_ENCRYPTION_KEY`: 인증 코드 암호화용 Fernet 키. 한 번 설정한 뒤 바꾸거나 분실하지 마세요.

키는 로컬에서 다음 명령으로 생성하고 Render 환경변수에만 저장합니다.

```powershell
py -3.10 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Render 시작 명령은 `python BOT/bot.py`, health check 경로는 `/healthz`입니다. UptimeRobot은 `https://<Render 서비스 주소>/healthz`를 5분 간격으로 확인하도록 설정합니다. 클라이언트 API는 `/v1/auth/redeem`, `/v1/auth/verify` 경로를 사용합니다.

무료 Render 서비스는 유휴 시 잠들 수 있고 첫 요청에 지연이 생길 수 있습니다. UptimeRobot은 테스트 중 sleep을 줄이는 용도이며 24시간 무중단을 보장하지 않습니다. 안정적인 상시 가동이 필요하면 Render 유료 상시 실행 플랜을 사용하세요.

비밀 값이 노출되면 Discord Developer Portal 또는 Supabase에서 즉시 재발급하세요.

## 로컬 개발 실행

PowerShell에서 환경변수를 설정한 뒤 서버를 실행할 수 있습니다. 로컬 실행에는 Discord 서버 ID와 관리자 역할 ID가 필요합니다.

```powershell
$env:DISCORD_BOT_TOKEN = "실제 토큰"
$env:DISCORD_GUILD_ID = "서버 ID"
$env:DISCORD_ADMIN_ROLE_ID = "관리자 역할 ID"
$env:CODE_ENCRYPTION_KEY = "생성한 Fernet 키"
$env:AUTH_DB_PATH = "$PWD\BOT\auth_server\auth.sqlite3"
$env:PORT = "8000"
py -3.10 -m pip install -r BOT/auth_server/requirements.txt
py -3.10 BOT/bot.py
```

인증 테스트는 `BOT` 폴더 안에서 실행합니다.

```powershell
Push-Location BOT
py -3.10 -m unittest auth_server.test_auth_flow
Pop-Location
```

Supabase 환경변수를 지정하지 않으면 개발용 SQLite를 사용합니다. Supabase로 로컬 테스트할 때는 `SUPABASE_URL`과 `SUPABASE_KEY`를 환경변수로 지정하세요. 로컬 주소 `http://127.0.0.1:8000`은 개발용으로만 사용하고 외부에는 HTTPS를 사용하세요.

## 클라이언트 설정 및 빌드

프로젝트 루트의 `auth_config.json`에서 API base URL을 실제 HTTPS 주소로 바꿉니다. 앱은 매 실행 때 서버에 접속하므로 오프라인에서는 인증할 수 없습니다.

```json
{
  "api_base_url": "https://auth.example.com"
}
```

`core/app_version.py`의 버전을 올린 뒤 Windows에서 Visual Studio C++ Build Tools를 설치하고 `packaging/build_release.bat`을 실행하면 인증 필수 EXE와 ZIP이 생성됩니다. 배포본에는 앱의 권장 기본 `settings.json`이 포함되며 개발 PC의 개인 설정은 복사하지 않습니다. 첫 업데이트 기능이 포함된 빌드는 기존 버전에 업데이터가 없으므로 테스터에게 한 번 수동 배포해야 합니다.

후속 업데이트는 ZIP을 HTTPS로 접근 가능한 릴리스에 올리고 SHA-256을 계산합니다.

```powershell
Get-FileHash .\배포용\KURO_HELPER.zip -Algorithm SHA256
```

Discord `/setappupdate`에서 버전, 강제 적용 기준, ZIP HTTPS 주소, SHA-256, 안내 문구를 지정합니다. 앱은 실행 시 선택 업데이트를 안내합니다. 강제 대상 앱은 실행 중이면 다음 30초 인증 확인 때 종료되고, 다시 실행할 때 ZIP을 내려받아 해시를 확인한 뒤 교체합니다. `settings.json`과 `보스돌이 기록`은 보존됩니다. `/clearappupdate`는 새 업데이트 정책을 중지합니다.

## 제한 사항

서버 검증, 일회용 코드, 관리자 역할 권한, PC 1대 등록은 일반적인 무단 공유를 막는 데 도움이 됩니다. 무제한 코드는 분실/유출에 대비해 관리 ID를 안전하게 보관하고 필요하면 즉시 취소하세요. EXE는 사용자 PC에서 실행되므로 숙련된 사용자의 바이너리 분석을 완전히 막지는 못합니다. 서버 비밀 키를 EXE에 넣지 말고 HTTPS를 사용하세요.
