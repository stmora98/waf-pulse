import pytest
from azure.core.exceptions import HttpResponseError, ServiceRequestError, ServiceResponseError

from waf_pulse import graph


class FakeClock:
    """Replaces time so the limiter and the retry waits run instantly."""

    def __init__(self):
        self.now, self.slept = 0.0, []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


@pytest.fixture()
def clock(monkeypatch):
    fake = FakeClock()
    monkeypatch.setattr(graph, "_now", fake.monotonic)
    monkeypatch.setattr(graph, "_sleep", fake.sleep)
    monkeypatch.setattr(graph, "_limiter", graph._Limiter(3, 5.0))
    monkeypatch.setattr(graph.random, "uniform", lambda a, b: 0)
    return fake


class Throttled(HttpResponseError):
    def __init__(self, headers=None):
        super().__init__(message="Client application has been throttled")
        self.status_code = 429
        self.response = type("R", (), {"headers": headers or {}})()


class FakeClient:
    def __init__(self, outcomes):
        self.outcomes, self.calls = list(outcomes), 0

    def resources(self, request):
        self.calls += 1
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class Page:
    def __init__(self, data, skip_token=None):
        self.data, self.skip_token = data, skip_token


def test_limiter_never_exceeds_the_window(clock):
    for _ in range(7):
        graph._limiter.acquire()
    # 3 calls per 5 seconds: calls 4-6 wait for the window, call 7 for the next one
    assert clock.now == pytest.approx(10.0, abs=0.2)


def test_retry_after_reads_the_quota_header_and_falls_back():
    assert graph.retry_after_seconds(Throttled({"x-ms-user-quota-resets-after": "00:00:07"})) == 7
    assert graph.retry_after_seconds(Throttled({"x-ms-user-quota-resets-after": "00:01:30"})) == 60  # capped
    assert graph.retry_after_seconds(Throttled({"Retry-After": "12"})) == 12
    assert graph.retry_after_seconds(Throttled({"Retry-After": "soon"})) == graph.DEFAULT_WAIT_SECONDS
    assert graph.retry_after_seconds(RuntimeError("no response")) == graph.DEFAULT_WAIT_SECONDS


def test_is_throttle_detects_429_and_text():
    assert graph.is_throttle(Throttled())
    assert graph.is_throttle(RuntimeError("(RateLimiting) too many requests"))
    assert not graph.is_throttle(RuntimeError("(BadRequest) invalid query"))


def test_throttled_call_waits_and_succeeds(clock):
    client = FakeClient([Throttled({"x-ms-user-quota-resets-after": "00:00:04"}), Page([1])])
    result = graph._execute(client, object())
    assert result.data == [1] and client.calls == 2
    assert 4 in clock.slept


def test_non_throttle_errors_are_raised_immediately(clock):
    client = FakeClient([HttpResponseError(message="(BadRequest) invalid")])
    with pytest.raises(HttpResponseError):
        graph._execute(client, object())
    assert client.calls == 1


def test_dropped_connections_are_retried(clock):
    client = FakeClient([ServiceResponseError("Connection aborted. RemoteDisconnected"), ConnectionError("reset"), Page([1])])
    assert graph._execute(client, object()).data == [1]
    assert client.calls == 3 and len(clock.slept) == 2


def test_other_exceptions_are_not_retried(clock):
    client = FakeClient([ValueError("bug")])
    with pytest.raises(ValueError):
        graph._execute(client, object())
    assert client.calls == 1


def test_a_connection_that_never_recovers_eventually_fails(clock):
    client = FakeClient([ServiceRequestError("down") for _ in range(graph.MAX_ATTEMPTS)])
    with pytest.raises(ServiceRequestError):
        graph._execute(client, object())
    assert client.calls == graph.MAX_ATTEMPTS


def test_gives_up_after_the_maximum_attempts(clock):
    client = FakeClient([Throttled() for _ in range(graph.MAX_ATTEMPTS)])
    with pytest.raises(HttpResponseError):
        graph._execute(client, object())
    assert client.calls == graph.MAX_ATTEMPTS


def test_query_follows_pagination_and_caps_rows(clock, monkeypatch):
    client = FakeClient([Page([1, 2], "t1"), Page([3, 4], "t2"), Page([5], None)])
    monkeypatch.setattr(graph, "_client", lambda credential: client)
    assert graph.query(None, "sub", "q") == [1, 2, 3, 4, 5]
    client = FakeClient([Page([1, 2], "t1"), Page([3, 4], "t2")])
    monkeypatch.setattr(graph, "_client", lambda credential: client)
    assert graph.query(None, ["a", "b"], "q", max_rows=3) == [1, 2, 3]
