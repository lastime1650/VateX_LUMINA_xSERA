# 오프라인 실행 보고서 생성

```text
python tools/build_intelligence_report.py --evidence execution.json --junit regression.xml --output report.html
```

이 도구는 입력 근거만 읽어 단일 한국어 HTML을 생성합니다. 서버 시작,
텔레메트리 생성, 운영 데이터 조회, 네트워크 요청 또는 private 디렉터리
검사는 수행하지 않습니다. 동일한 입력으로 동일한 HTML 바이트를 만듭니다.
CSS·JavaScript가 내장되며 외부 CDN이나 추적 기능이 없습니다.

입력 JSON은 최상위 object입니다. 다음 구조를 권장하지만 알 수 없는
필드는 전체 부록에 그대로 남습니다. 민감 값은 제외됩니다.

| 필드 | 권장 내용 |
|---|---|
| source_version / source_hash | 실제 실행한 소스 버전과 manifest hash |
| changes | 다섯 개발 단계의 title/name, description, 파일·결과 정보 |
| simulation | 가상 장비별 counts, 전송 start/end, 전체 events 또는 timeline |
| events 또는 simulation.events | 실제 event_id, device/source/sourcetype/host, sent_at/received/event_time |
| checks | name, passed boolean 또는 status, detail/evidence/reason |
| signals | 실제 id, kind, event_ids, parent_signal_ids, story_id, metadata.incident_id |
| stories | 실제 id와 상세 근거 |
| cases | 실제 id, contributions[].evidence.event_ids 및 analysis.signal_id/story_id |
| ml | status, models, runs; duration_ms와 worker_wall_ms를 분리 |
| shadow / ueba / case_regroup | 실제 실행 결과와 제한 사항 |

시간 숫자는 기록된 epoch seconds 또는 명시적 elapsed_seconds여야 하며,
문자열 시각은 시간대가 포함된 ISO 8601을 사용합니다. 타임라인 우선순위는
sent_at → sent → received → event_time → at → timestamp → elapsed_seconds →
elapsed 입니다. 시각 기준은 각 점의 상세 기록에서 표시합니다. 절대
시각은 Asia/Seoul로 렌더링합니다. 시각 레코드가 없으면 차트를 만들지 않습니다.

그래프는 실제 ID 참조만 연결합니다. 같은 IP·호스트·원본 집합 중첩만으로
Signal이 Case를 생성했다고 추론하지 않습니다. 화면은 120개 노드까지
종류별로 균형 있게 표시하고 검색/필터로 범위를 좁힐 수 있습니다. 전체
노드와 연결은 내장 근거 부록에 포함됩니다.

JUnit의 testcase 요소를 직접 집계하며 failure, error, skipped를
구분합니다. skipped에 기록된 xfail도 건너뜀에 포함됩니다. 보고서에서
테스트 이름·상태·사유 검색과 상세 확인이 가능합니다. suite header와
testcase 숫자가 다른 경우 testcase 실기록을 기준으로 합니다.

password, token, secret, credential, private key, authorization, cookie 등
민감 이름의 값과 PEM private key, inline credential 문자열을 제거합니다.
JSON 문자열로 중첩된 object/list도 검사합니다. 본문은 textContent로
표시하고 내장 JSON의 `<`, `>`, `&`, 유니코드 줄 구분자를 escape하여
`</script>` 삽입을 차단합니다. JUnit DOCTYPE/entities와 과도한 크기의
입력은 거부합니다.

모든 시뮬레이션은 synthetic=true, native hardware=false로 명시합니다.
합성 로그 결과를 상용 센서 품질·미지 공격 정확도·Yocto 이미지/BSP
자격으로 표현하지 않습니다. CPU ML의 재구성 오차는 악성 확률이 아니며,
학습/holdout 검증을 악성 Precision/Recall 평가로 대체하지 않습니다.
