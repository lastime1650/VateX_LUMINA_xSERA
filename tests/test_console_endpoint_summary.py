# ruff: noqa: F811 -- Shared fixture injection is resolved by pytest argument name.
import copy
import time

import pytest

from sapientia import console_data, endpoint_response
from sapientia.storage import encode
from tests.test_agent_distribution import config, source_store  # noqa: F401
from tests.test_endpoint_response import response_case  # noqa: F401
from tests.test_xdr_bridge import actor


@pytest.mark.parametrize(
    "kind,executed,mutations,reads",
    [
        ("terminate_process", True, 1, 0),
        ("inspect_file", False, 0, 1),
        ("inspect_file", True, 0, 0),
        ("collect_artifact", False, 0, 1),
        ("terminate_process", False, 0, 0),
        ("terminate_process", "true", 0, 0),
    ],
)
def test_effect_counter_does_not_count_read_only_or_invalid_executed_receipts(
    response_case, kind, executed, mutations, reads, monkeypatch
):
    store, _, _, incident, body = response_case
    # Pure database schema fixture; this test never polls or dispatches an executor.
    with monkeypatch.context() as command_schema:
        command_schema.delenv("SAPIENTIA_BLOCK_NATIVE_RESPONSE", raising=False)
        command = endpoint_response.create(store, actor(), incident, body)
    action = copy.deepcopy(command["action"])
    action["type"] = kind
    with store.control() as db:
        db.execute(
            "UPDATE endpoint_responses SET state='succeeded',action=?,result=? WHERE id=?",
            (
                encode(action),
                encode(
                    {
                        "success": True,
                        "executed": executed,
                        "type": kind,
                        "code": "fixture",
                        "detail": "synthetic aggregator input",
                    }
                ),
                command["id"],
            ),
        )
    now = time.time()
    value = console_data.summary(store, actor(), now - 600, now + 1)["cases"][
        "endpoint_responses"
    ]
    assert value["by_state"]["succeeded"] == 1
    assert value["confirmed_effects"] == mutations
    assert value["read_only_completed"] == reads
