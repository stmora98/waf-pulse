import json

import pytest

from tools import update_checklists
from waf_pulse import checklists


GUIDS = (
    "4b69bad3-3aad-45e8-a68e-1d76667313b4",
    "a3592829-e6e2-4061-9368-6af46791f893",
    "a78b3d31-3170-44f2-b5d7-651a29f4ccf5",
)


@pytest.mark.parametrize("guid", GUIDS)
def test_import_preserves_query_fixes(guid):
    item = {"guid": guid, "text": "Control", "graph": "upstream query"}
    result = update_checklists.slim({"items": [item]}, "test")
    assert result["items"][0]["graph"] == update_checklists.QUERY_FIXES[guid]
    assert item["graph"] == "upstream query"


def test_import_keeps_unrelated_queries():
    item = {"guid": "other", "graph": " resources | project id "}
    assert update_checklists.slim({"items": [item]}, "test")["items"][0]["graph"] == "resources | project id"


@pytest.mark.parametrize("guid", GUIDS)
def test_all_shipped_copies_use_fixed_queries(guid):
    copies = [
        item
        for path in checklists.CHECKLIST_DIR.glob("*.json")
        for item in json.loads(path.read_text(encoding="utf-8"))["items"]
        if item["guid"] == guid
    ]
    assert copies
    assert all(item["graph"] == update_checklists.QUERY_FIXES[guid] for item in copies)


def test_fixed_queries_return_evaluable_resources():
    group_query, peering_query, backend_query = (update_checklists.QUERY_FIXES[guid] for guid in GUIDS)
    assert "| extend compliant = principalType" in group_query
    assert group_query.endswith("| project id, compliant")
    assert "tobool(" in peering_query and "== true" in peering_query
    assert "| union" not in backend_query
    assert "backendPoolCount > 0" in backend_query and "minPoolMembers > 1" in backend_query
    assert backend_query.endswith("| project id, compliant")


@pytest.mark.parametrize("guid", GUIDS)
def test_fixed_controls_count_compliant_and_noncompliant_resources(guid):
    item = next(item for item in checklists.load_items() if item["guid"] == guid)
    prefix = "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg"
    rows = [
        {"id": f"{prefix}/providers/Microsoft.Network/loadBalancers/good", "compliant": True},
        {"id": f"{prefix}/providers/Microsoft.Network/loadBalancers/bad", "compliant": False},
    ]
    findings, stats = checklists.evaluate("run", [(item["graph"], [item])], [rows])
    assert len(findings) == 1
    assert findings[0]["resourceId"] == rows[1]["id"]
    assert stats[0]["affected"] == 1
    assert stats[0]["applicable"] == 2
