# Agent 배포 서명과 무결성 검증

0.20.0의 production 패키지는 외부 Ed25519 개인 키가 없으면 생성되지 않는다. 서버의 `SAPIENTIA_AGENT_SIGNING_KEY_FILE`은 설치된 소스 밖의 절대 경로이며, 링크와 재분석 경로 및 다른 사용자가 수정할 수 있는 키 위치는 거부한다. 다운로드 ZIP에는 개인 키나 스스로 선택한 신뢰 키가 없다.

운영자는 별도 채널에서 서명자의 공개 키 지문을 확인하고 `xsera.agent.trust.v1` 공개 JSON을 추출·설치 디렉터리 밖의 보호된 절대 경로에 배치한다. Windows 설치의 `-TrustedKeysFile`, Linux의 `SERA_AGENT_TRUSTED_KEYS_FILE`이 그 파일을 지정한다. `SERA_AGENT_REQUIRE_SIGNED_PACKAGE=0`은 production 설치를 허용하지 않는다. installer/bootstrap도 독립적으로 인증한 릴리즈에서 가져와야 한다.

서명 메시지는 `signature`를 제외한 manifest의 UTF-8 JSON이다. 키 정렬, 쉼표·콜론 구분자, `ensure_ascii=False`, `allow_nan=False`로 직렬화한다. 공개 키는 32바이트 Ed25519이며 `key_id`는 공개 키 SHA-256의 앞 32개 소문자 16진 문자다. 서명은 엄격한 Base64로 저장한다. 기본 설치는 서명과 전체 archive 멤버의 SHA-256을 먼저 검증한 다음에만 설정·등록을 진행한다. configure 입력인 배포 JSON·일회용 토큰·CA도 같은 서명에 고정한다.

에이전트는 시작 때 서명과 설치된 `Agent/` 파일을 검증하며 실패하면 시작하지 않는다. 매 heartbeat에서 같은 측정을 다시 수행한다. 파일 변조, 신뢰 키 제거·폐기 또는 현재 무결성 설정의 변경은 실패와 degraded 상태로 보고된다. production의 미등록 `.pyc`와 `__pycache__`도 거부한다. 서비스는 `-B`로 실행하며 Agent 트리를 사전 컴파일하지 않는다. OS 코드 서명이나 하드웨어·메모리 무결성 보증은 제공하지 않는다.

키를 폐기할 때는 독립적으로 배포한 보호된 trust JSON의 `revoked_key_ids`에 해당 지문을 추가한다. 새 키로 교체할 때도 새 지문의 독립 확인과 외부 trust 배포를 먼저 진행한다. 서명자 폐기는 새 startup을 거부하고 다음 heartbeat를 실패로 만든다. 이미 실행 중인 관리자 권한 코드의 강제 종료나 물리적 호스트 차단을 뜻하지 않는다.

`Agent/requirements.txt`의 cryptography와 defusedxml 버전은 보호된 Python에 미리 설치해야 한다. privileged installer는 의존성을 다운로드하지 않고 정확한 버전을 확인한다. 실제 OS 서비스 설치, 방화벽 변경 및 호스트 격리는 이 검증 작업에서 수행하지 않았다. response·defense·kernel prevention 기본값은 계속 비활성이다.

개발 시험은 명시적인 `development_fixture` 패키지와 loopback 전용 runtime 설정만 사용한다. 이 패키지는 등록 권한을 담을 수 없고 production 서비스 설치로 전환할 수 없다. `tools/provision_agent_test_signer.py --qa-only --directory <새 외부 디렉터리>`는 버릴 수 있는 QA 키만 만들며, 운영 서명자나 자동 신뢰 등록을 만들지 않는다. 운영 키 생성·보관·백업·배포는 소유자의 별도 절차에 따른다.

최상위 오프라인 릴리즈 설치기는 신뢰한 bootstrap pip로 pip 없는 대상 환경에 서명된 wheel만 설치한다. bytecode 생성은 끄고, wheel RECORD와 설치된 파일 집합을 확인한다. 업데이트는 기존 데이터의 잠금을 유지한 백업 경계 digest를 저장하며, 활성화 시 같은 잠금 안에서 기존 데이터가 달라지면 재준비를 요구한다. 중단 후 복구도 설치된 코드와 검증된 데이터 상태를 재검사한다. 새 기록을 버리는 자동 rollback은 허용하지 않는다.
