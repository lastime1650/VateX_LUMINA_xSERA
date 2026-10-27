# LUMINA 0.2 운영 검토 안내

이 문서는 0.2 소스의 실행 계약과 검토 절차입니다. 예시 주소·계정·경로는 운영 설정이 아니며 실제 자격증명은 포함하지 않습니다. 현재 실행 중인 0.1 서버에 이 문서의 명령을 자동 적용하지 않습니다.

**Linux 최신 소스 검증, ISO 생성·설치·VMware 부팅 및 공개 저장소/Release 발행은 보류 상태입니다.** 기존 README의 사용자 검토 게이트가 우선합니다. 이번 변경이나 아래 단일 호스트 시험으로 배포 승인, 엔터프라이즈 완성 또는 Splunk 우위를 선언하지 않습니다.

## 실행과 저장소

Python 3.12 이상에서 프로젝트의 고정 의존성을 설치한 전용 가상환경을 사용합니다. 서비스 계정에는 소스·설정·인증서 읽기와 해당 데이터 디렉터리 쓰기 권한만 부여합니다. 개인 키와 비밀 환경 변수는 서비스 관리자/비밀 저장소가 주입하며 예제 JSON, 명령행 인자, 로그 또는 저장소에 값을 넣지 않습니다.

```powershell
python -m sapientia --data "D:\SapientiaReview\data" serve --host 127.0.0.1 --port 8788
```

이 예시는 별도 로컬 검토 인스턴스입니다. 원격 서비스는 이름과 일치하는 인증서로 직접 HTTPS를 제공합니다.

```powershell
python -m sapientia --data "D:\SapientiaReview\data" serve --host 0.0.0.0 --port 8788 --cert "D:\SapientiaReview\tls\server.pem" --key "D:\SapientiaReview\tls\server.key"
```

인스턴스별로 SQLite 수락 대기열/제어 DB와 DuckDB 이벤트 DB를 같은 데이터 디렉터리에 둡니다. 한 데이터 디렉터리는 한 서비스 프로세스가 소유합니다. Uvicorn 다중 프로세스/worker 확장은 지원하지 않으며 CLI는 `workers=1`을 사용합니다. `--query-workers`는 그 프로세스 안의 검색 동시 실행 한도입니다. 프록시 전달 헤더는 신뢰하지 않습니다. 기존 `sapientia.service`는 Linux 구성 초안이며 새 TLS/설정 경로를 반영하고 최신 Linux 시험을 통과한 뒤 사용해야 합니다.

### CLI 전체 옵션

전역 옵션 `--data PATH`는 하위 명령 앞에 둡니다. 기본값은 현재 작업 디렉터리의 `data`입니다. `-h`/`--help`는 전역 및 각 하위 명령에서 도움말을 출력합니다.

| 명령/옵션 | 기본값 | 동작과 범위 |
| --- | --- | --- |
| `serve` | — | 한 프로세스로 API, 인덱서, 스케줄러와 선택한 수신기를 실행 |
| `serve --host` | `127.0.0.1` | HTTP/API 수신 주소. 원격 주소에는 `--cert`와 `--key` 모두 필요 |
| `serve --port` | `8787` | API 포트. 검토 인스턴스는 운영 포트와 다른 포트 사용 |
| `serve --cert`, `--key` | 없음 | HTTPS 서버 인증서 체인과 개인 키 경로 |
| `serve --cluster PATH` | 없음 | 기존 NATS JetStream 전체 복제 설정 JSON. GUI 가입 정보만으로 데이터 복제가 켜지지 않음 |
| `serve --oidc-config PATH` | 없음 | 아래 OIDC 설정 JSON. 없으면 `SAPIENTIA_OIDC_CONFIG` 환경 변수의 파일 경로도 조회 |
| `serve --federation-config PATH` | 없음 | 아래 정적 검색 연합 설정 JSON. 없으면 기능 비활성 |
| `serve --query-workers` | `4` | 검색 슬롯 수, `1..32`; 포화 요청은 503으로 거부 |
| `serve --memory-limit` | `512MB` | DuckDB 메모리 설정 문자열. 전체 Python 프로세스 RSS 한도가 아님 |
| `serve --max-queue` | `100000` | 전체 미색인 수락 대기열 건수, 최대 `10000000` |
| `serve --max-tenant-queue` | `25000` | 테넌트별 대기열 건수, `1..max-queue` |
| `serve --indexing-batch` | `5000` | 한 색인 배치의 최대 건수, `1..100000` |
| `serve --indexing-idle` | `0.25` | 대기열이 비었을 때 대기 시간(초), `0.01..5` |
| `serve --syslog-host` | `127.0.0.1` | 선택적 Syslog 수신 주소 |
| `serve --syslog-port` | 없음 | 지정 시에만 수신기 시작. `0..65535`; 0은 임시 시험 포트 |
| `serve --syslog-transport` | `tls` | `udp`, `tcp`, `tls`. 원격 바인딩은 `tls`만 허용 |
| `serve --syslog-tenant` | `default` | 해당 수신기의 모든 이벤트가 속할 고정 테넌트 |
| `serve --syslog-cert`, `--syslog-key` | 없음 | Syslog TLS 인증서/키. `tls` 선택 시 둘 다 필수 |
| `serve --appliance-setup` | 꺼짐 | 신뢰된 관리망의 직접 HTTPS에서 첫 관리자 등록을 허용. 초기 등록 범위를 넓히는 명시적 옵션 |
| `create-user NAME` | — | 로컬 계정 생성. 서비스가 정지된 데이터 디렉터리에서 실행 |
| `create-user --tenant` | `default` | 계정 테넌트 |
| `create-user --role` | `admin` | `admin`, `analyst`, `viewer`. 최소 권한 역할을 명시 |
| `status` | — | `default` 테넌트 저장소 상태 출력. 실행 서비스에 접속하는 명령이 아니므로 서비스 정지 후 사용 |
| `backup DESTINATION` | — | 새 디렉터리로 일관된 오프라인 백업 |
| `backup --encrypt` | 꺼짐 | 새 파일로 암호화 백업. 암호는 터미널의 숨김 입력으로만 받음 |
| `restore SOURCE` | — | `--data`의 아직 존재하지 않는 디렉터리로 복구 |
| `restore --encrypted` | 꺼짐 | SOURCE를 암호화 백업 파일로 읽고 암호를 숨김 입력으로 받음 |

`create-user`의 암호는 12..128자이며 `getpass`로 두 번 입력합니다. 관리자 API로 발급한 초기 암호에는 변경 의무가 있으므로 해당 절차를 완료한 뒤 업무 API를 사용합니다. `status`, `create-user`, `backup`도 저장소 프로세스 잠금을 획득하므로 실행 중인 서비스의 데이터 경로를 공유하지 않습니다. 온라인 상태 조회는 인증된 `/api/health`, `/api/operations`를 사용합니다.

### 대기열과 검색 한도

수락 성공과 검색 가능 시점은 다릅니다. HTTP 수집 응답은 영속 대기열 수락을 확인하며, 이후 인덱서가 분석 DB에 반영합니다. 재전송에는 안정적인 `event_id`를 사용하고 중복 수락 결과를 확인합니다. 전체/테넌트 대기열, 디스크 여유 또는 검색 슬롯이 부족하면 실패를 숨기지 않고 클라이언트가 오류를 받습니다.

인덱서는 대기열이 남으면 한 배치 뒤에도 계속 처리하되 기본 0.25초 작업 예산과 최대 배치 횟수 사이에서 제어를 반환합니다. 단일 DB 배치 작업의 실행 시간을 강제로 0.25초로 자르는 계약은 아닙니다. 작업 취소와 종료 시그널을 확인하며, 비어 있을 때 `--indexing-idle`만큼 기다립니다. 일반 검색의 기본 시간 한도는 15초이고 결과 한도는 1000행입니다. `query_timeout`, `indexing_budget`, 보존 기본값 등은 현재 CLI 옵션이 아닙니다.

`/api/operations`는 테넌트/인덱스 범위의 대기열, 규칙 실행 상태, 실패 횟수와 재시도 시각을 제공합니다. 노드 전체 색인량/EPS/수신기 통계는 `default` 테넌트의 전체 인덱스 권한 관리자만 봅니다. EPS는 최근 실행 구간의 관측치이며 용량 보장값이 아닙니다. 실패 규칙은 별도 재시도 상태에 따라 지연되고, 원래 검색 창을 보존합니다. 저장 규칙/검색 작업은 실행 시 소유자의 현재 권한을 다시 확인합니다.

`storage_bytes`는 해당 순간의 일반 파일 크기 추정치입니다. WAL/임시 파일이 조회 도중 사라지면 그 항목을 건너뛰며, 디렉터리 전체의 원자적 스냅샷이나 실제 할당 디스크 블록 수는 아닙니다. 이벤트/대기열 건수는 별도의 권한 적용 DB 조회 결과입니다.

## Syslog 수신

```powershell
python -m sapientia --data "D:\SapientiaReview\data" serve --host 127.0.0.1 --port 8788 --syslog-host 0.0.0.0 --syslog-port 6514 --syslog-transport tls --syslog-tenant default --syslog-cert "D:\SapientiaReview\tls\syslog.pem" --syslog-key "D:\SapientiaReview\tls\syslog.key"
```

CLI 원격 수신은 TLS 1.2 이상만 허용합니다. **현재 CLI Syslog TLS는 서버 인증이며 클라이언트 인증서 검증(mTLS)은 구성하지 않습니다.** 인증서 검증을 하는 송신기를 사용하고 방화벽/관리망에서 허용 송신지를 제한합니다. TCP 연결만으로 송신자의 테넌트 신원을 판별하지 않으며 테넌트는 수신기 설정으로 고정됩니다. UDP/TCP 평문은 loopback 시험용입니다.

TCP/TLS는 RFC6587 octet-counting 및 줄바꿈 프레이밍을 지원합니다. 기본 수신 버퍼는 1000건, 한 프레임은 최대 65536바이트, 연결은 최대 32개입니다. 이 값들과 `source=syslog`, 자동 형식 판별은 `SyslogSettings` 기본값이며 현재 CLI에서 별도 변경하지 않습니다. 파서가 벤더의 모든 필드/시간 형식을 완전 지원한다는 의미는 아닙니다.

TCP는 버퍼가 찼을 때 읽기를 지연합니다. UDP는 역압력/전달 보장이 없고 폐기 카운터를 확인해야 합니다. 네트워크 수신 자체가 영속 수락 ACK는 아닙니다. 수신기 내부 큐는 DB 수락 전 메모리에 존재하므로 강제 종료 시 손실 가능성이 있습니다. 정상 종료는 수신기를 먼저 닫고 가능한 프레임을 DB에 수락시킨 뒤 인덱서를 정지합니다. 정해진 종료 시간 안에 수락을 마치지 못한 오류를 무시하지 않습니다.

## OIDC와 로컬 접근 권한

[`oidc.example.json`](oidc.example.json)을 비공개 운영 설정 위치로 복사하고 공급자의 정확한 issuer, client ID, callback과 고정 `sub`를 입력합니다. 예제의 환경 변수 항목은 **변수 이름**이며 실제 비밀 값이 아닙니다. 구성 파일 자체도 계정 매핑/내부 주소를 포함하므로 쓰기 권한을 운영자로 제한합니다.

지원 흐름은 Authorization Code + S256 PKCE, 상태/nonce/브라우저 바인딩, JWKS 기반 RS256/ES256 ID 토큰 검증입니다. issuer의 discovery 정보와 토큰 issuer/audience/시간/서명을 검증합니다. `algorithms`는 공급자가 사용하는 알고리즘만 허용합니다. `client_secret_env`를 지정하면 `client_secret_basic`을 사용하며, 생략한 공개 클라이언트는 공급자가 `none` 인증을 지원해야 합니다. 비밀이 필요한 환경 변수 누락은 시작 오류입니다.

1. 서비스 정지 중 로컬 계정을 만들거나 관리자 API로 계정을 준비합니다. 예제 `analyst_example`은 자동 생성되지 않습니다.
2. 해당 계정의 테넌트·역할·활성 상태와 인덱스 ACL을 설정합니다. OIDC의 그룹/역할/사용자명 주장으로 로컬 권한을 올리지 않습니다.
3. 공급자에서 정확한 `https://siem.example:8787/api/sso/callback` 주소를 등록하고 설정 JSON의 `redirect_uri`와 일치시킵니다. 실제 브라우저 접속도 같은 HTTPS 서비스로 수행합니다.
4. 공급자와 callback의 신뢰된 HTTPS 인증서를 준비합니다. 공급자 통신은 시스템 CA와 호스트명 검증을 사용하며 리디렉션/환경 프록시는 따르지 않습니다. 이 어댑터에는 별도 `ca_file` 옵션이 없습니다.
5. `--oidc-config`로 실행하고 `/api/sso/status`, `/api/sso/start` 및 실제 공급자 로그인을 검토합니다. 공급자 장애/미등록 subject는 로그인 실패로 처리합니다.

`subjects`는 공급자의 변하지 않는 `sub`에서 **기존 로컬 계정 이름**으로의 고정 매핑입니다. 삭제/비활성 계정은 로그인할 수 없습니다. 계정의 기존 TOTP가 활성화되었으면 OIDC 후에도 로컬 TOTP 절차를 수행합니다. 현재 구현은 한 issuer 설정이며 자동 사용자 프로비저닝, SCIM, 임의 IdP/다중 issuer 또는 그룹 동기화를 제공하지 않습니다. `allow_loopback_http=true`는 별도 로컬 시험 전용이며 원격 운영 설정에는 사용하지 않습니다.

인덱스 ACL API는 같은 테넌트 관리자의 `GET/PUT /api/users/{name}/indexes`입니다. PUT 본문 예시는 `{"allowed_indexes":["main","security"]}`이며 로그인 세션의 `X-CSRF-Token`이 필요합니다. 정확한 인덱스 이름만 허용합니다. `[]`는 모두 거부, `["*"]`는 해당 테넌트의 전체 인덱스입니다. **기존 활성 계정에 ACL 행이 없으면 호환 기본값이 `["*"]`**이므로 제한할 계정에는 명시적으로 설정합니다. ACL 변경은 대상의 기존 세션을 폐기하며 다시 로그인해야 합니다. OIDC 설정에서 이 ACL을 대체하지 않습니다.

## 정적 검색 연합(federation)

[`federation.example.json`](federation.example.json)은 독립 데이터 파티션 A가 B를 조회하고 반대 방향의 요청도 제한적으로 수락하는 구성 예시입니다. 설정은 운영자가 오프라인으로 관리하고 재시작 시 읽습니다. GUI 가입, Master/Slave 이름이나 사용자의 URL 입력으로 peer가 추가되지 않습니다. `--federation-config`를 지정하지 않으면 비활성입니다.

`peers`는 이 노드가 조회할 원격 목록이고 `grants`는 **이 노드가 수락할 원격 전용 키의 권한**입니다. 구성 속성 이름은 `grants`이며 `incoming`이 아닙니다. A의 peer 항목 `key_id=region-a-to-region-b`는 B의 grant에서 같은 key ID와 같은 전용 비밀을 사용해야 합니다. 반대 방향은 별도 키/환경 변수로 설정합니다. 예제를 양쪽에 그대로 복사하면 짝이 맞는 구성이 되지 않습니다.

전용 비밀은 각 방향/peer 쌍마다 독립적으로 생성하고 32..512개의 공백 없는 출력 가능한 ASCII 문자로 서비스 환경에 주입합니다. 수집 토큰, OIDC 비밀, 복제 서명 키와 공유하지 않습니다. `secret_env`는 환경 변수 이름만 담습니다. 비밀 교체는 양쪽 설정과 환경을 함께 계획하고 서비스를 재시작합니다. 자동 키 교체/다중 유효 키 기간은 없습니다.

| 설정 | 기본값/한도 | 의미 |
| --- | --- | --- |
| `local_name` | `local` | 응답의 노드 식별자. peer 이름과 중복하지 않음 |
| `include_local` | `true` | 로컬 데이터도 합산할지 선택 |
| `peers` | `[]` | 정적 HTTPS origin, 이름, recipient `key_id`, `secret_env`, `tenants`, `indexes` |
| `grants` | `[]`, 최대 32개 | 수신할 `key_id`, `secret_env`, `tenants`, `indexes` |
| `timeout` | 10초, `0.1..30` | 한 검색의 전체 예산 |
| `max_results` | 1000, `1..1000` | 전역 반환 행 상한 |
| `max_groups` | 1000, `1..1000` | 정확한 count를 위한 그룹 수 상한 |
| `concurrency` | 2, `1..8` | 이 Federation 객체의 동시 fan-out 검색 수 |
| `clock_skew` | 60초, `1..120` | 서명 요청의 시간 허용 범위. 양쪽 시간 동기화 필요 |
| `allow_loopback_http` | `false` | `127.0.0.1`/`::1`의 명시적 HTTP 시험만 허용 |

최대 조회 노드는 **로컬 포함 8개**입니다. `tenants`와 `indexes`는 정확한 이름 목록이고 와일드카드는 허용하지 않습니다. HTTPS는 기본 시스템 CA를 검증하며, peer의 `ca_file`에 전용 신뢰 CA 파일을 지정할 수 있습니다. 상대 경로 `ca_file`은 설정 파일 디렉터리를 기준으로 해석합니다. 호스트명 검증은 유지합니다. URL에는 사용자정보, 경로, query 또는 fragment를 넣지 않습니다. 리디렉션과 환경 프록시는 사용하지 않습니다.

사용자는 일반 로그인/CSRF로 `POST /api/federation/search`를 호출합니다. origin은 사용자의 현재 테넌트/인덱스 권한과 peer 설정을 교차 제한하고, 원격 `POST /api/federation/peer/search`는 자신의 grant로 다시 제한합니다. 원격 요청에는 전용 Bearer 비밀과 본문/recipient/path를 묶은 HMAC, timestamp, nonce가 모두 필요하며 재생 요청을 거부합니다. 일반 수집 키는 이 데이터 경로에 사용할 수 없습니다. origin 및 원격 조회는 각각 감사에 기록됩니다.

예를 들어 JSON 필터에 맞는 모든 이벤트의 count는 `group_by: []`로 요청합니다. `group_by: ["source"]`는 source별 count입니다. 별도의 `aggregate` 속성은 없습니다.

```json
{
  "language": "json",
  "earliest": 0,
  "latest": 2000000000,
  "limit": 1000,
  "query": {
    "filters": [{"field": "severity", "op": "gte", "value": 5}],
    "group_by": ["source"]
  }
}
```

첫 버전의 연합 검색은 JSON 이벤트 필터/투영과 그룹별 **count**만 지원합니다. 전체 SPL, sum/avg/distinct 등 임의 분산 집계는 거부합니다. count는 각 노드의 부분 count를 전역 합산하고, 노드/전역 그룹 상한을 넘으면 잘린 수치를 반환하지 않고 실패합니다. 이벤트 반환은 `event_time`/`received` 정렬과 노드/이벤트 ID를 이용해 전역 top-K를 합치며 `_node`, `_federated_id`를 추가합니다. K는 최대 1000이고 완전한 커서/전체 결과 페이지 순회 계약은 없습니다. 응답은 2MiB 한도입니다. 어느 노드의 오류, 시간 초과 또는 상한 초과도 성공한 부분 응답으로 표시하지 않습니다.

**전체 복제 노드들을 서로 다른 파티션처럼 등록하면 같은 이벤트가 노드별로 중복 계산됩니다.** 노드가 다르면 같은 event ID도 독립 항목입니다. 연합은 자동 샤딩, 복제본 소유권 판단, 복제 데이터 중복 제거, 자동 멤버십, 서비스 failover 또는 HA를 제공하지 않습니다. 정확한 전역 count가 필요하면 서로 겹치지 않는 데이터셋/파티션만 구성하거나 대표 노드 하나만 조회합니다.

## 백업, 복구와 독립 감사 체크포인트

백업은 오프라인 방식입니다. 수집 송신을 중지/보류하고 서비스를 정상 종료한 뒤 프로세스 종료를 확인합니다. 실행 중인 파일을 일반 복사하여 SQLite/DuckDB 일관성을 가정하지 않습니다. CLI는 데이터 디렉터리 프로세스 잠금으로 동시 사용을 거부합니다.

백업은 스키마 초기화·마이그레이션 없이 SQLite 스냅샷과 DuckDB 체크포인트 후 파일 복사로 기존 스키마·데이터를 보존하며, 세션 폐기는 복원 시에만 수행합니다.

```powershell
python -m sapientia --data "D:\SapientiaReview\data" backup "E:\SapientiaBackup\review-001.sap" --encrypt
python -m sapientia --data "D:\SapientiaRestore\review-001" restore "E:\SapientiaBackup\review-001.sap" --encrypted
```

백업 파일과 복구 디렉터리는 **아직 존재하지 않아야** 합니다. 암호는 12..1024자이며 `getpass`로 읽고 백업 시 확인 입력을 받습니다. 암호를 인자/환경 변수/파일에 자동 기록하지 않습니다. 형식은 scrypt + AES-256-GCM 인증 암호화이며 스트리밍 archive의 크기 제한은 64GiB 미만입니다. 복호화 인증, 파일 manifest SHA256, 감사 체인/포함 체크포인트를 검증한 후 새 복구 디렉터리를 게시합니다. 암호 분실 시 복구 수단은 없습니다.

`--encrypt`를 생략하면 새 디렉터리의 평문 백업입니다. 백업은 로그뿐 아니라 사용자/토큰 정보와 `secrets.key`, 존재하는 노드 가입 파일을 포함합니다. 암호화 작업 중에도 제한된 임시 평문 스냅샷을 사용하므로 원본 볼륨/백업 목적지 권한과 저장 매체 암호화를 관리합니다. 서비스 환경 변수, OIDC/federation JSON, TLS 개인 키, 외부 NATS 저널은 이 데이터 백업에 자동 포함되지 않습니다. 각각 별도로 보호·보존합니다.

복구는 세션과 진행 중 OIDC 로그인 상태를 폐기합니다. 기존 수집 토큰 등 모든 자격증명을 자동 교체하는 동작은 아니므로 백업 유출/사고 복구에서는 별도 폐기·교체를 계획합니다. 원래 운영 데이터 디렉터리를 덮어쓰지 말고 격리된 주소에서 복구 검증 후 서비스 전환을 결정합니다. 전체 복제 클러스터로 복구본을 연결하기 전에는 아래의 저널/체크포인트 정합성을 검토합니다.

감사 체인은 로컬 해시 연결입니다. 데이터와 함께 보관된 manifest/checkpoint만으로 공격자가 전체 이력을 다시 쓴 경우까지 증명하지 못합니다. 독립 보관 checkpoint를 별도 권한/장비에 유지해야 하며, 이는 WORM 보장이 아닙니다.

온라인 API는 appliance 관리자(`default` 테넌트의 admin)의 `POST /api/audit/checkpoint`, `POST /api/audit/verify`, `GET /api/audit/integrity`입니다. checkpoint 응답 JSON을 데이터 디렉터리 밖의 독립 보관 위치로 옮기고, 검증 API에는 그 JSON을 그대로 제출합니다. 세션 변경 요청에는 CSRF가 필요합니다.

완전히 정지된 서비스/복사본에서의 읽기 전용 확인은 다음처럼 `AuditSnapshot`을 사용합니다. 이것은 `Store()`로 서비스를 새로 열거나 스키마를 마이그레이션하지 않습니다.

```python
from pathlib import Path
from sapientia.backup import AuditSnapshot
from sapientia.audit_integrity import verify

snapshot = AuditSnapshot(Path(r"D:\SapientiaRestore\review-001"))
result = verify(snapshot, Path(r"E:\IndependentAudit\checkpoint-001.json"))
assert result["valid"] and result["checkpoint_verified"], result
```

처음 독립 체크포인트를 만들 때도 정지된 `AuditSnapshot`에 `create_checkpoint(snapshot)`를 호출하고 결과 JSON을 데이터 디렉터리 밖에 새 파일로 저장합니다. 원본 검증이 실패하면 새 checkpoint로 문제를 덮지 말고 실패 증거를 보존합니다. checkpoint의 sequence가 복구본보다 최신이면 검증 실패가 정상이며, 일치하는 시점의 checkpoint/백업을 선택해야 합니다.

## 기존 전체 복제 클러스터의 0.2 전환 계획

`--cluster`의 JetStream 복제와 위의 federation은 별개입니다. 기존 복제는 공유 저널의 서명된 제어/수락 트랜잭션을 각 노드가 적용하고 각자 이벤트 분석 파일을 갖는 전체 복제 방식입니다. GUI Master/Slave 가입은 제어 정보이며 그 자체로 부하분산기, 자동 샤딩 또는 자동 서비스 HA를 구성하지 않습니다. 브로커 quorum 동작과 클라이언트의 노드 전환은 별도로 검증해야 합니다.

0.2는 ACL·실행 소유권·탐지·연합 재생 방지 등 추가 제어 테이블을 사용합니다. 저널의 SQL을 이전 바이너리가 재생할 수 있다는 보장은 없으므로 **모든 앱 노드를 함께 정지·업그레이드**하는 유지보수 창을 사용합니다. 혼합 버전 rolling upgrade를 수행하지 않습니다.

1. 각 노드의 버전, `node_id`, `cluster_id`, 저널 sequence와 오류 상태를 기록하고 동일한 저널 끝까지 추격했는지 확인합니다. 수집/사용자 변경을 멈춘 뒤 모든 앱 노드를 정상 종료합니다.
2. 이전 버전에 맞는 절차로 각 노드의 일관된 오프라인 데이터 백업을 보존합니다. 새 코드가 기존 디렉터리를 처음 열기 **전** 상태가 필요합니다. 별도로 NATS JetStream 저널의 일관된 백업/스냅샷, 서버 설정, 서명 비밀과 독립 감사 checkpoint를 보호합니다. 앱 백업만으로 브로커 저널을 대신하지 않습니다.
3. 격리 복구본에서 0.2의 스키마 초기화와 기존 저널 재생을 먼저 검증합니다. 기존 모든 규칙에 유효한 소유자가 식별되는지 확인합니다. 소유자를 입증할 수 없는 이전 규칙은 임의 관리자 권한으로 실행하지 않고 차단되므로 권한 있는 사용자가 검토·재저장합니다.
4. 모든 앱 노드에 같은 0.2 소스/패키지 및 호환 의존성을 배치하고, 시작 전에 각 노드의 설정과 환경 비밀을 준비합니다. 최초 앱 노드의 초기화/재생을 확인한 후 나머지도 같은 버전으로 시작하고 각각 추격 완료를 확인합니다. 이 단계에서도 클라이언트 쓰기는 중지 상태로 유지합니다.
5. 계정/인덱스 ACL, 수집 영속 ACK 및 안정 ID 재전송, 검색 결과, 규칙 재시도/창, 감사 체인, 각 노드의 동일 sequence를 확인한 뒤 수집을 재개합니다. 변경 중 잃어버린 세션은 다시 로그인합니다.
6. 롤백은 이전 패키지만 기존 0.2 데이터에 얹는 방식이 아닙니다. 승인된 같은 시점의 앱 백업과 저널 상태를 **함께** 복구하는 별도 절차가 필요합니다. 그 뒤 수락된 쓰기가 있다면 유실/중복 없이 재전송할 방법을 먼저 결정합니다. 검증되지 않은 저널 자르기/삭제를 수행하지 않습니다.

기존 복제 JSON의 핵심 필드는 `node_id`, `cluster_id`, `servers`, `replicas`(1/3/5)입니다. 원격 `servers`는 검증된 `tls://`를 사용하고 `ca`, 선택적 클라이언트 `cert`/`key`를 구성합니다. NATS 토큰은 `token_env`(기본 `SAPIENTIA_NATS_TOKEN`), 저널 서명 키는 `signing_key_env`(기본 `SAPIENTIA_CLUSTER_KEY`)로 주입하며 서명 키는 32바이트 이상입니다. 저널은 재생 연속성을 요구하므로 보존 정책/용량을 임의로 줄이거나 purge하지 않습니다. 새 클러스터/노드 추가는 기존 복제 문서의 검증된 fresh-directory/checkpoint 절차를 따릅니다.

## 100,000건 HTTP/TLS 검토 프로파일

2026-10-08 소스 버전 0.2.0을 Windows 11, Python 3.12.14의 임시 단일 노드 서비스에서 합성 이벤트 100,000건, 배치 500건, 사용자 4명, 검색 슬롯 4개, 사용자당 후속 검색 20회로 최종 측정했습니다. TLS 인증서 검증을 켰고 운영 8787 서비스/데이터를 대상으로 삼지 않았습니다. 호스트 CPU/I/O를 전용 예약한 시험은 아닙니다. 최종 원본은 `qualification-final-100000.json`과 동명의 `.server.log`입니다.

| 관측값 | 결과 |
| --- | --- |
| 영속 수락 | 18.653초, 5,361.15 events/s |
| 전송 시작부터 전체 검색 가능 | 19.122초, 5,229.70 events/s |
| 수집 중 검색 지연 p50 / p95 | 106.11 / 190.40 ms, 132개 표본 |
| ACK 배치의 검색 가시성 지연 p50 / p95 | 464.10 / 740.40 ms, 200개 배치 표본 |
| 수집 후 4명 동시 검색 | 80/80 성공, p50 127.71 / p95 193.79 ms |
| 관측 최대 대기열 / 종료 대기열 | 3,500 / 0건; 상태 표본 26개 |
| 정확성 | count=100000, distinct event ID=100000, sequence 합=4999950000 |
| 같은 500건 재전송 | 새 수락 0, 중복 500 |
| ACK 뒤 강제 종료/재시작 | 종료 후 영속 대기열 500건을 확인; 재생 후 총 100500건, 재전송 중복 500건 |

강제 종료는 Windows 가상환경 launcher뿐 아니라 미리 보유한 실제 Python 자식 프로세스 핸들로 해당 임시 서버를 종료합니다. 재시작 전에 프로세스 종료, 리스너 폐쇄와 SQLite 파일의 배타적 열기 성공을 확인했습니다. 두 서버 세대 모두 이 검사를 통과했습니다. 종료 후 대기열이 0건이면 영속 재생을 시험한 것으로 간주하지 않으며, 현재 `--crash-drill`의 전체 통과에는 실제 미처리 대기열이 남아 있어야 합니다.

sequence 합은 산술 일관성 점검이며 암호학적 이벤트 내용 checksum이 아닙니다. 배치 가시성 지연은 이벤트별 전체 지연 분포가 아닙니다. 약 20초의 단일 실행은 장시간 soak, TB급 데이터, 실제 외부 수집기, 네트워크 분할/quorum 장애 또는 Splunk 대조 시험을 대체하지 않습니다. 보고서의 `enterprise_ready`와 `splunk_comparison`은 `false`입니다.

이전에 검색 슬롯 2개로 수행한 10,000건/사용자 4명 시험은 후속 검색 80회 중 19회의 HTTP 503이 발생하여 실패로 남겼습니다. 이후 4슬롯 프로파일에서 10,000건 및 위의 100,000건은 해당 요청을 모두 처리했습니다. 서로 다른 실행의 EPS 차이를 슬롯 변경만의 효과로 해석하지 않습니다. 용량을 넘는 요청의 503을 숨기거나 성공으로 재분류하지 않습니다.

검토 중 Windows launcher만 종료하던 이전 도구의 문제가 확인되어, 과거 smoke/10,000/100,000건 보고서의 **강제 종료·재시작·재생 주장을 미검증으로 정정**했습니다. 원래 HTTP 측정/오류 수치는 유지하고 `lifecycle_review` 및 원래 판정 필드로 정정 이유를 기록했습니다. 위 최종 실행은 실제 자식 종료를 검증한 도구를 사용합니다.

또한 최종 검토 중 100,000건 실행 한 차례에서 수집 중 모니터가 HTTP 500을 한 번 받아 전체 실패로 기록했습니다(`qualification-final-100000-monitor-failure.json`). 당시 도구가 임시 서버 로그를 정리하여 **그 500의 원인은 확정하지 못했습니다.** 이후 로그를 보존하도록 도구를 수정했고 재현 시도는 통과했습니다. 별도로 WAL 파일이 파일 크기 조회 사이에 사라지면 `/api/health`에서 `FileNotFoundError`가 발생하는 경로를 결정적 시험으로 재현하여 수정했습니다. 이 재현이 앞선 500의 원인을 입증하는 것은 아닙니다. 수정 전 실패 증거 `health-filesystem-race-before.xml`, 수정 후 관련 저장소/API/운영/정규화/도구 시험 77개 통과 기록 `qualification-health-focused.xml`과 수정 후 위 최종 100,000건 통과를 함께 보존합니다. 최종 실행의 모니터 오류는 0건이지만 앞선 실패를 삭제하거나 성공으로 재분류하지 않습니다.

재측정 도구는 명시적 `--isolated`가 있어야 자체 임시 서비스/데이터를 생성하고 해당 자식 프로세스만 강제 종료합니다. 기존 서비스 URL/데이터 경로 입력은 받지 않습니다. 검토용 환경에서 다음과 같이 실행하며 다른 시험과 경합 여부도 기록합니다.

```powershell
python tools/qualification.py --isolated --count 100000 --batch 500 --users 4 --rounds 20 --query-workers 4 --transport https --crash-drill --output "reports/qualification-100000-review.json"
```

도구의 추가 `--timeout` 기본값은 60초입니다. `--transport http`는 loopback 개발 시험이고 위 TLS 프로파일과 동일한 결과로 취급하지 않습니다. JSON 원본의 실패·HTTP 오류·표본 수와 시험 환경을 함께 보존합니다. 최신 Linux·외부 IdP·독립 장비 간 연합/전체 복제·장시간 부하·복구 시간 검증과 사용자 검토가 남아 있으며, ISO/공개 발행 게이트는 계속 보류합니다.

전달 산출물의 파일명은 `qualification-health-focused.xml` → `health-and-integration-final.xml`, `health-filesystem-race-before.xml` → `health-race-reproduction-before.xml`, `qualification-final-100000-monitor-failure.json` → `qualification-monitor-failure.json`입니다. 최종 전체 회귀 결과는 `regression-0.2.0.xml`을 확인합니다. 별도 백업 시험과 위 후속 시험은 전체 회귀와 중복하므로 시험 수를 합산하지 않습니다.
