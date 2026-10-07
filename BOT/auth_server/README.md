# KURO HELPER Discord 인증 서버

이 서버는 Discord 봇과 HTTPS 인증 API를 한 프로세스에서 실행합니다. 인증 코드는 Supabase에 해시로 저장합니다. Discord bot token과 Supabase service-role key는 Render 환경변수에만 저장하고 클라이언트 EXE나 GitHub에는 넣지 않습니다.

## 인증 흐름

1. 관리자가 `/registercode @테스터 [유효기간]`을 실행하고 비공개 모달에 직접 정한 16~64자 코드를 입력합니다.
2. 서버에는 코드 원문이 아닌 SHA-256 해시만 저장됩니다. 모달은 Discord 채널에 코드 내용을 게시하지 않습니다.
3. 관리자가 등록한 코드를 테스터에게 직접 전달합니다. 등록되지 않았거나 이미 사용/만료된 코드는 앱에서 거부됩니다.
4. 테스터가 KURO HELPER에 코드를 입력하면 API가 Discord 계정을 최초 PC 한 대에 연결하고 30일 세션을 발급합니다.
5. 이후 프로그램을 실행할 때마다 API에서 세션과 PC 등록을 확인합니다. 세션 토큰은 Windows DPAPI로 현재 사용자 계정에 묶어 저장합니다.
6. 관리자는 `/resetdevice @사용자`로 PC를 초기화할 수 있습니다. 초기화 뒤 새 코드를 `/registercode`로 등록해 전달해야 합니다.

허가를 취소하려면 관리자는 `/revokeuser @사용자`를 사용합니다. 이 명령은 세션을 폐기하고 라이선스를 비활성화합니다. 앱 실행 중인 PC는 현재 실행을 계속할 수 있고, 다음 실행 시 서버 확인에서 차단됩니다. 이미 등록된 코드는 사용자당 미사용 코드 1개까지 유지됩니다.

## Discord 설정

1. Discord Developer Portal에서 새 Application을 만들고 Bot을 추가합니다.
2. Bot token을 발급합니다. 토큰은 이 저장소에 입력하거나 EXE에 포함하지 마세요.
3. 봇을 본인 Discord 서버에 초대합니다. `bot`과 `applications.commands` scope를 선택하고, slash command 사용에 필요한 기본 권한만 부여합니다.
4. 서버 설정에서 `인증 관리자` 역할을 만들고 코드를 등록/초기화/취소할 관리자에게 부여합니다.
5. Developer Mode를 켜고 서버 ID 및 관리자 역할 ID를 복사합니다.

## Supabase 테스트 DB 설정

1. Supabase 프로젝트의 SQL Editor를 엽니다.
2. `BOT/auth_server/supabase_schema.sql` 전체를 실행합니다. 테이블, 접근 정책, 트랜잭션 RPC가 준비됩니다.
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

Render 시작 명령은 `python BOT/bot.py`, health check 경로는 `/healthz`입니다. UptimeRobot은 `https://<Render 서비스 주소>/healthz`를 5분 간격으로 확인하도록 설정합니다. 클라이언트 API는 `/v1/auth/redeem`, `/v1/auth/verify` 경로를 사용합니다.

무료 Render 서비스는 유휴 시 잠들 수 있고 첫 요청에 지연이 생길 수 있습니다. UptimeRobot은 테스트 중 sleep을 줄이는 용도이며 24시간 무중단을 보장하지 않습니다. 안정적인 상시 가동이 필요하면 Render 유료 상시 실행 플랜을 사용하세요.

비밀 값이 노출되면 Discord Developer Portal 또는 Supabase에서 즉시 재발급하세요.

## 로컬 개발 실행

PowerShell에서 환경변수를 설정한 뒤 서버를 실행할 수 있습니다. 로컬 실행에는 Discord 서버 ID와 관리자 역할 ID가 필요합니다.

```powershell
$env:DISCORD_BOT_TOKEN = "실제 토큰"
$env:DISCORD_GUILD_ID = "서버 ID"
$env:DISCORD_ADMIN_ROLE_ID = "관리자 역할 ID"
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

그 뒤 `packaging/build_release.bat`을 실행하면 해당 주소가 포함된 인증 필수 EXE와 ZIP이 생성됩니다. 주소가 예시/로컬 값인 상태에서는 배포 빌드가 중단되어, 인증할 수 없는 EXE를 실수로 전달하지 않도록 합니다.

## 제한 사항

서버 검증, 일회용 코드, 관리자 역할 권한, PC 1대 등록은 일반적인 무단 공유를 막는 데 도움이 됩니다. 코드는 예측하기 어렵게 16자 이상으로 정하고 테스터별로 다르게 사용하세요. 하지만 EXE는 사용자 PC에서 실행되므로, 숙련된 사용자가 바이너리를 분석하거나 인증 코드를 수정하는 것까지 완전히 방지할 수는 없습니다. 서버 토큰을 EXE에 넣지 말고, HTTPS와 관리자 계정 보호를 유지하세요.
