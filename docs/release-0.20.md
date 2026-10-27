# xSERA 0.20 CPU 관찰 배포

이 배포는 CPU 실행과 실제 호스트 변경 차단을 유지합니다. 운영 에이전트의 프로세스
종료·삭제·격리·방화벽·커널 기능을 자동으로 켜지 않습니다. 조사용 원본 수집·파일
검사·Case 생성과 명시적인 가상 대응은 사용할 수 있습니다.

## 신뢰 설정

외부에서 신뢰한 Python 3.12와 cryptography, 별도로 신뢰한 `tools/deploy_release.py`를
준비하십시오. 다운로드에 포함된 공개키만 그대로 신뢰하지 말고 배포 소유자와 독립적인
경로로 지문을 대조한 뒤, 설치 및 다운로드 디렉터리 밖의 보호된 공개 신뢰 파일에
등록하십시오. 서명 개인키는 배포 패키지에 포함하지 않습니다. 개발용 시험키의 결과는
소유자 운영 서명 또는 OS 코드 서명 인증으로 인정하지 않습니다.

공개 신뢰 파일의 schema는 `xsera.release.trust.v1`, `keys`는 키 ID와 32바이트
Ed25519 공개키의 16진수 값 매핑입니다. ID는 공개키 SHA-256의 앞 32자리입니다.
`revoked_key_ids`는 폐기 목록이고 `minimum_release_sequence`는 허용 최소 배포 순서입니다.
키 교체 시 새 공개키를 먼저 별도 배포하고, 이전 키 폐기·최소 순서를 갱신하십시오.

## 설치·업데이트·복구

관리되는 서버를 중지한 뒤, 비어 있는 전용 설치 디렉터리에 설치합니다. 공개키 경로와
다운로드 경로, 목적지는 실제 환경에 맞게 지정합니다. 준비와 활성화를 분리해 검토할
경우 `--prepare-only`로 준비하고 출력된 transaction을 `activate`에 전달합니다.

```powershell
python tools/deploy_release.py verify --bundle C:\xSERA-download --trust-file C:\xSERA-trust\release.json
python tools/deploy_release.py install --bundle C:\xSERA-download --trust-file C:\xSERA-trust\release.json --destination C:\xSERA-install --prepare-only
python tools/deploy_release.py activate --destination C:\xSERA-install --transaction <출력된ID>
python tools/deploy_release.py launch --destination C:\xSERA-install -- --host 127.0.0.1 --port 8443
```

신규 설치는 기존 관리자·운영 인증서를 제공하지 않습니다. 실제 노출 전 관리자를
명시적으로 만들고 TLS·접근 제어를 구성하십시오. 설치 도구는 서비스 등록·방화벽
변경을 수행하지 않습니다. `launch`는 관찰 프로필 환경을 강제합니다. 사용자 지정
실행 경로로 이 환경을 제거하면 해당 실행은 이 배포 프로필의 검증 범위를 벗어납니다.

업데이트는 `update`를 사용합니다. 기존 데이터는 보존하고 스냅샷을 새 데이터 위치로
복원해 검증합니다. 준비 후 기존 데이터가 바뀌면 활성화하지 않습니다. 중단된 작업은
`recover --transaction <ID>`로 상태를 정합화합니다. `rollback`은 새 버전이 받은 데이터가
없을 때만 이전 코드·데이터로 돌아갑니다. 새 기록이 있으면 먼저 보존·정합 처리해야
합니다. 이 절차는 실제 정전 시험, 분산 HA 또는 외부 백업을 대체하지 않습니다.

기존 비관리 0.19 설치는 운영 데이터를 직접 가리키지 마십시오. 서버 중지·독립 백업·
새 관리 디렉터리의 복원본을 이용한 사전 검증 후 전환합니다. 자동 파일 덮어쓰기나
기존 개인 데이터 디렉터리 탐색은 수행하지 않습니다.

관찰 배포는 기존 에이전트에 이미 저장된 오프라인 방어 정책을 즉시 철회하지는
않습니다. 과거에 실제 방어를 활성화한 에이전트가 있다면 업데이트 전에 해당 호스트의
defense/kernel 설정 비활성화 또는 정책 만료를 확인해야 합니다. 신규 패키지는
이 기능을 꺼서 제공합니다. 실제 운영 에이전트 서비스 설치·전환은 별도 현장 검증입니다.

## 공개 소스와 선택 기능

CPU 모델용 공개 의존성은 PyTorch `2.13.0+cpu`입니다. 온라인으로 별도 구성하는
경우 공식 CPU wheel 인덱스 `https://download.pytorch.org/whl/cpu`를 명시해야 합니다.
기본 PyPI의 GPU용 패키지를 대신 설치하지 마십시오. 제공되는 오프라인 Windows
패키지는 CPU wheel과 해시가 고정된 전체 의존성을 포함합니다.

프로젝트 소유 소스는 Apache-2.0이며 기존 원저작자 표기를 보존합니다. YARA의 DRL1.1·
MIT·BSD 규칙, MITRE 자료, capa 규칙은 각 원래 고지와 조건을 유지합니다. pySigma
변환 라이브러리(LGPL-2.1-only)는 외부 Sigma 규칙의 라이선스와 별개입니다. 원래
소스·라이선스를 제공하고 라이브러리 교체·수정 및 해당 LGPL 권리 행사를 금지하지
않습니다. 변경한 전체 소스에서 다시 빌드해 자신의 신뢰키로 서명할 수 있습니다.

오프라인 CPU 패키지는 capa `9.4.0+xsera.cpu1`과 pySigma `2.0.1+xsera.cpu1`
패키징 변형을 사용합니다. 원래 Python 구현은 바이트 단위로 같으며, 사용하지 않는
IDA 의존성과 MITRE 온라인 보강의 diskcache 의존성만 메타데이터에서 제외했습니다.
각 원본·변경 고지·재패키징 스크립트를 제공합니다. 지원 범위는 xSERA의 headless CPU
파일 분석 및 제한된 Sigma 변환이며, IDA 플러그인·온라인 MITRE 보강·범용 외부 Sigma
검증기는 포함하지 않습니다. 원래 Apache/LGPL 조건은 그대로 유지합니다. 이전 일반
pySigma에서 변환만 한 미승인 초안은 다시 변환·검토해야 합니다. 기존 활성화된
네이티브 규칙과 역사적 변환 버전 표기는 자동 변경하지 않습니다.

ClamAV·CAPE 서비스, 게스트 OS, 실제 센서와 Yocto BSP는 이 Windows 오프라인 패키지에
포함하지 않습니다. 자체 OS 레이어는 실제 Linux wheelhouse별 라이선스·소스 제공 검토가
완료돼야 패키징할 수 있으며, BSP 부팅·커널·하드웨어 검증은 별도 현장 항목입니다.
# 설치된 패키지의 검증 기록과 원본 식별

공식 설치기는 `pip --no-compile`로 설치하고 `python -I -B`로 실행합니다.
독립 서명된 검증 기록을 등록할 때는 wheel의 `.dist-info/xsera-source-manifest.json`,
표준 RECORD, 실제 애플리케이션 파일의 전체 목록과 SHA-256을 매번 대조합니다.
일반 pip 설치에서 생성된 `.pyc` 등 추가 파일은 이 엄격한 파일 목록 검사를 통과하지
않으므로 공식 설치·실행 방식을 사용해야 합니다. 개발 소스 트리는 기존 전체 원본
재계산을 유지하며, 설치 메타데이터가 없을 때 버전 번호나 환경 변수의 digest로
대체하지 않습니다.

이 메타데이터 자체가 배포자 인증 서명은 아닙니다. 서명 검증한 설치 패키지와 보호된
설치 경로, 그리고 별도 검증 담당자의 Ed25519 서명이 원본 식별값을 함께 고정합니다.
검증 담당자의 공개 키 파일은 `serve --qualification-keys <외부 공개 키 JSON>`으로
명시하며, JSON은 `{"검증담당자ID":"base64로 인코딩한 32바이트 공개 키"}` 형식입니다.
릴리즈 서명 키와 검증 담당자의 키는 서로 다른 목적입니다. 개인 키는 이 파일에
포함하지 않습니다. 공식 설치기의 `launch` 명령에도 이 서버 옵션을 전달할 수 있습니다.
가상 검증 기록의 `native:false`는 실제 호스트 보호 검증이나 차단 허용을 뜻하지 않습니다.

