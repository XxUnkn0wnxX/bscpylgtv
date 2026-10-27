import asyncio
import json

import pytest

from bscpylgtv import WebOsClient
from bscpylgtv.manifest import MANIFEST


BLACKLISTED_CERTIFICATE = "403 Pairing rejected: blacklisted certificate detected"


class FakeStorage:
    def __init__(self):
        self.keys = []

    async def set_key(self, key, value):
        self.keys.append((key, value))

    async def get_key(self, key):
        return None

    async def list_keys(self):
        return {}


class FakeWebSocket:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.sent = []

    async def send(self, payload):
        self.sent.append(json.loads(payload))

    async def recv(self):
        return json.dumps(next(self.responses))

    async def close(self):
        pass


async def run_connect(monkeypatch, responses, client_key=None, storage=None, manifest=None):
    ws = FakeWebSocket(responses)

    async def fake_connect(*args, **kwargs):
        return ws

    async def finish_consumer(_ws):
        return None

    monkeypatch.setattr("bscpylgtv.webos_client.websockets.connect", fake_connect)
    client = WebOsClient("tv", states=[], client_key=client_key, storage=storage)
    if manifest is not None:
        client.manifest = manifest
    client.ping_interval = None
    monkeypatch.setattr(client, "consumer_handler", finish_consumer)
    result = asyncio.Future()
    await client.connect_handler(result)
    return client, ws, result


@pytest.mark.asyncio
@pytest.mark.parametrize("pairing_type", ["PROMPT", "PIN"])
async def test_signed_manifest_registration_succeeds_without_fallback(monkeypatch, pairing_type):
    if pairing_type == "PIN":
        monkeypatch.setattr("builtins.input", lambda _prompt: "1234")
    responses = [
        {"type": "response", "payload": {"pairingType": pairing_type}},
        {"type": "registered", "payload": {"client-key": "new-key"}},
    ]
    client, ws, result = await run_connect(monkeypatch, responses)

    assert result.exception() is None
    assert client.client_key == "new-key"
    assert ws.sent[0]["payload"]["manifest"] == MANIFEST
    assert len([msg for msg in ws.sent if msg.get("id") == "register_0"]) == 1
    if pairing_type == "PIN":
        assert ws.sent[1]["id"] == "register_1"


@pytest.mark.asyncio
@pytest.mark.parametrize("old_key", [None, "stored-key"])
async def test_blacklisted_signed_manifest_retries_unsigned_once(monkeypatch, old_key):
    storage = FakeStorage()
    responses = [
        {"type": "error", "error": BLACKLISTED_CERTIFICATE},
        {"type": "registered", "payload": {"client-key": "new-key"}},
    ]
    client, ws, result = await run_connect(monkeypatch, responses, client_key=old_key, storage=storage)

    registrations = [msg for msg in ws.sent if msg.get("id") == "register_0"]
    assert result.exception() is None
    assert len(registrations) == 2
    assert registrations[0]["payload"]["manifest"] == MANIFEST
    assert registrations[1]["payload"]["manifest"] == {
        key: value for key, value in MANIFEST.items() if key not in ("signed", "signatures")
    }
    assert registrations[1]["payload"]["client-key"] == old_key
    assert registrations[1]["payload"]["pairingType"] == registrations[0]["payload"]["pairingType"]
    assert client.manifest == registrations[1]["payload"]["manifest"]
    assert client.client_key == "new-key"
    assert storage.keys == [("tv", "new-key")]
    assert "signed" in MANIFEST and "signatures" in MANIFEST
    assert WebOsClient("other", states=[]).manifest is MANIFEST


@pytest.mark.asyncio
async def test_retry_error_is_reported_instead_of_accepting_stored_key(monkeypatch):
    responses = [
        {"type": "error", "error": BLACKLISTED_CERTIFICATE},
        {"type": "error", "error": "401 Pairing denied"},
    ]
    _client, ws, result = await run_connect(monkeypatch, responses, client_key="stored-key")

    assert result.exception().message == "401 Pairing denied"
    assert len([msg for msg in ws.sent if msg.get("id") == "register_0"]) == 2


@pytest.mark.asyncio
async def test_second_blacklist_response_does_not_retry_again(monkeypatch):
    responses = [
        {"type": "error", "error": BLACKLISTED_CERTIFICATE},
        {"type": "error", "error": BLACKLISTED_CERTIFICATE},
    ]
    _client, ws, result = await run_connect(monkeypatch, responses)

    assert result.exception().message == BLACKLISTED_CERTIFICATE
    assert len([msg for msg in ws.sent if msg.get("id") == "register_0"]) == 2


@pytest.mark.asyncio
async def test_custom_manifest_and_other_errors_do_not_fallback(monkeypatch):
    custom_manifest = dict(MANIFEST)
    _client, ws, result = await run_connect(
        monkeypatch,
        [{"type": "error", "error": BLACKLISTED_CERTIFICATE}],
        client_key="stored-key",
        manifest=custom_manifest,
    )
    assert result.exception().message == BLACKLISTED_CERTIFICATE
    assert len([msg for msg in ws.sent if msg.get("id") == "register_0"]) == 1

    _client, ws, result = await run_connect(
        monkeypatch,
        [{"type": "error", "error": "401 Unauthorized"}],
        client_key="stored-key",
    )
    assert result.exception().message == "401 Unauthorized"
    assert len([msg for msg in ws.sent if msg.get("id") == "register_0"]) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("returned_key", [None, "", 123])
async def test_registered_response_requires_nonempty_string_key(monkeypatch, returned_key):
    _client, _ws, result = await run_connect(
        monkeypatch,
        [{"type": "registered", "payload": {"client-key": returned_key}}],
        client_key="stale-key",
    )

    assert result.exception().message == "Unable to pair"


@pytest.mark.asyncio
async def test_explicit_client_key_can_register_without_storage(monkeypatch):
    client, _ws, result = await run_connect(
        monkeypatch,
        [{"type": "registered", "payload": {"client-key": "explicit-key"}}],
        client_key="explicit-key",
    )

    assert result.exception() is None
    assert client.client_key == "explicit-key"
