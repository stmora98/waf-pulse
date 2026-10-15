import data


class FakeContainer:
    def __init__(self, items):
        self.items = items

    def query_items(self, query, parameters=None, partition_key=None):
        return list(self.items)

    def read_item(self, item, partition_key=None):
        return dict(self.items[0])


class FakeDatabase:
    def __init__(self, items):
        self.items = items

    def get_container_client(self, name):
        return FakeContainer(self.items)


COSMOS_SYSTEM_FIELDS = {"_rid": "r", "_self": "s", "_etag": "e", "_attachments": "a", "_ts": 1}


def test_public_removes_cosmos_system_fields():
    cleaned = data.public({"id": "1", "title": "x", **COSMOS_SYSTEM_FIELDS})
    assert cleaned == {"id": "1", "title": "x"}


def test_every_read_path_strips_system_fields(monkeypatch):
    doc = {"id": "run1", "status": "completed", "startedUtc": "t", "severity": "high", **COSMOS_SYSTEM_FIELDS}
    monkeypatch.setattr(data, "_db", lambda: FakeDatabase([doc]))

    for result in (data.latest_run(), data.summary("run1"), *data.findings("run1")):
        assert not any(key.startswith("_") for key in result)
