# Saved finding 공통 신호 연결

`intelligence_findings.run_due`는 기존 `findings`와 `rule_execution`을
읽고 `intelligence_cursors`의 `findings` 위치를 사용합니다. 별도 모델이나
가상 원본을 만들지 않습니다. 각 저장 검색 결과는 실제 원본 이벤트를
다시 확인한 뒤 `kind=finding` 공통 Signal로 연결할 수 있습니다.

연결 조건은 현재 저장 검색이 활성이고 그 실행 소유자가 전체 finding
인덱스 범위에 권한을 가지며, 같은 범위에 독립 승인된 활성 intelligence
정책이 존재하는 것입니다. `access_scope`는 정확한 인덱스 목록이어야
합니다. sample에는 실제 event_id, event_time, host, source, index가
있어야 하고 다시 조회한 원본과 동일해야 합니다. Signal의 읽기 범위를
표본만으로 축소하여 전체 finding의 비공개 집계/존재를 노출하지 않도록,
전체 finding 범위와 표본 원본들의 인덱스 집합이 같아야 합니다.

집계 전용 결과, wildcard 범위, 원본 ID가 없는 표본, 변조된 원본
식별자, 철회된 소유자·검토자와 승인 범위가 없는 finding은 제외 사유를
내구성 진단으로 남깁니다. 저장 finding이 최대 10개 표본만 보존하므로
Signal도 해당 **표본 부분집합**만 근거로 삼습니다. matched_at_least를
전체 원본 개수로 오해하거나 없는 ID를 추정하지 않습니다.

항목별 성공/제외와 커서 변경을 같은 트랜잭션에 기록합니다. 일시적인
용량/실행 오류는 최대 세 번 시도한 뒤 명시적으로 제외하며, 권한이나
원본 오류 하나가 다른 테넌트의 뒤따르는 finding을 계속 막지 않습니다.
`intelligence_decisions`에서 finding_exported, finding_retry,
finding_excluded와 원인을 확인할 수 있습니다.

`validate_parent(db, actor, body)`는 bool을 반환합니다. Finding 부모는
현재 false_positive 판정, 검색 비활성화, 검색 정의 변경, 범위 축소,
bridge 정책 개정·승인 철회를 다시 확인합니다. Legacy 부모는 현재
기여 근거 ID, 이동 이후 현재 Case 범위와 판정, 개별 근거의
false_positive/expected_activity 판정을 확인합니다. 선택적으로
`metadata.contribution_evidence_digest`에 저장 근거 문자열의 SHA-256을
넣으면 같은 원본 ID를 유지한 근거 맥락 변경도 거부합니다.
