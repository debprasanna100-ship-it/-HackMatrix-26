"""Phase 4 chain integration tests: hash recomputation, commit + verify endpoints.

Uses a stub registry client so no blockchain/network is needed in unit tests;
the live local-chain flow is exercised separately.
"""
from __future__ import annotations

import json
import sqlite3
import time

import httpx
import pytest

from app.web3.registry import parse_report_hash, recompute_report_hash
from tests.test_api import build_app, good_fetch_result
from tests.test_api import StubFetcher  # noqa: F401  (re-exported fixture helper)


class StubRegistryClient:
    """In-memory ThreatRegistry stand-alone: submit/verify/get_chain_id."""

    def __init__(self, chain_id: int = 31337):
        self.chain_id = chain_id
        self.submitted: list[tuple[str, str]] = []
        self._committed: set[bytes] = set()

    def is_connected(self) -> bool:
        return True

    def get_chain_id(self) -> int:
        return self.chain_id

    def submit(self, report_hash: bytes, category: str) -> dict:
        if report_hash in self._committed:
            raise RuntimeError("AlreadySubmitted (stub)")
        self._committed.add(report_hash)
        self.submitted.append((report_hash.hex(), category))
        return {
            "tx_hash": "0x" + "ab" * 32,
            "block_number": 7,
            "gas_used": 100_000,
            "block_timestamp": 1_700_000_000,
        }

    def verify(self, report_hash: bytes) -> dict:
        if report_hash in self._committed:
            return {
                "exists": True,
                "reporter": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
                "submitted_at": 1_700_000_000,
                "category": "url-analysis",
                "status": "submitted",
                "revision_count": 0,
            }
        return {"exists": False}


async def create_report(client: httpx.AsyncClient, url: str = "https://example.com/") -> dict:
    resp = await client.post("/api/v1/analyze/url", json={"url": url})
    assert resp.status_code == 200, resp.text
    return resp.json()


# ---- hash recomputation -------------------------------------------------------


@pytest.mark.asyncio
async def test_recomputed_hash_matches_integrity(tmp_path):
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        report = await create_report(c)

    recomputed = recompute_report_hash(report)
    stored = report["integrity"]["canonical_json_sha256"]
    assert recomputed == stored
    assert len(recomputed) == 64


def test_parse_report_hash_validation():
    good = "0x" + "a" * 64
    assert parse_report_hash(good) == b"\xaa" * 32
    assert parse_report_hash("A" * 64) == b"\xaa" * 32  # bare hex, upper-case accepted
    with pytest.raises(ValueError):
        parse_report_hash("0x1234")            # too short
    with pytest.raises(ValueError):
        parse_report_hash("0x" + "g" * 64)     # non-hex
    with pytest.raises(ValueError):
        parse_report_hash("not-a-hash")


# ---- commit endpoint ----------------------------------------------------------


@pytest.mark.asyncio
async def test_commit_disabled_returns_503(tmp_path):
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        report = await create_report(c)
        resp = await c.post(f"/api/v1/reports/{report['report_id']}/commit")
    assert resp.status_code == 503
    assert resp.json()["error"]["code"] == "chain_disabled"


@pytest.mark.asyncio
async def test_commit_roundtrip_and_idempotence(tmp_path):
    application = build_app(
        tmp_path,
        fetcher=StubFetcher(good_fetch_result()),
        registry_address="0xThreatRegistry",
    )
    application.state.registry_client = StubRegistryClient()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        report = await create_report(c)
        report_id = report["report_id"]

        resp = await c.post(f"/api/v1/reports/{report_id}/commit")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["report_id"] == report_id
        assert body["report_hash"] == "0x" + report["integrity"]["canonical_json_sha256"]
        assert body["tx_hash"].startswith("0x")
        assert body["contract_address"] == "0xThreatRegistry"
        assert body["chain_id"] == 31337

        # Second commit is rejected (already committed).
        resp2 = await c.post(f"/api/v1/reports/{report_id}/commit")
        assert resp2.status_code == 409
        assert resp2.json()["error"]["code"] == "already_committed"


@pytest.mark.asyncio
async def test_commit_unknown_report_404(tmp_path):
    application = build_app(tmp_path, registry_address="0xThreatRegistry")
    application.state.registry_client = StubRegistryClient()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.post("/api/v1/reports/deadbeef/commit")
    assert resp.status_code == 404


# ---- verify endpoint ----------------------------------------------------------


@pytest.mark.asyncio
async def test_verify_by_report_id_roundtrip(tmp_path):
    application = build_app(
        tmp_path,
        fetcher=StubFetcher(good_fetch_result()),
        registry_address="0xThreatRegistry",
    )
    application.state.registry_client = StubRegistryClient()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        report = await create_report(c)
        report_id = report["report_id"]
        await c.post(f"/api/v1/reports/{report_id}/commit")

        resp = await c.get(f"/api/v1/verify/{report_id}")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["mode"] == "report_id"
        assert body["integrity_match"] is True
        assert body["on_chain"]["exists"] is True
        assert body["on_chain"]["category"] == "url-analysis"
        assert body["on_chain"]["status"] == "submitted"
        assert body["commitment"]["tx_hash"] == "0x" + "ab" * 32


@pytest.mark.asyncio
async def test_verify_by_report_id_not_committed(tmp_path):
    application = build_app(
        tmp_path,
        fetcher=StubFetcher(good_fetch_result()),
        registry_address="0xThreatRegistry",
    )
    application.state.registry_client = StubRegistryClient()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        report = await create_report(c)
        resp = await c.get(f"/api/v1/verify/{report['report_id']}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["integrity_match"] is True
        assert body["on_chain"]["exists"] is False
        assert body["commitment"] is None


@pytest.mark.asyncio
async def test_verify_by_raw_hash(tmp_path):
    application = build_app(tmp_path, registry_address="0xThreatRegistry")
    stub = StubRegistryClient()
    application.state.registry_client = stub
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        known = "0x" + "11" * 32
        stub._committed.add(bytes.fromhex("11" * 32))  # simulate a foreign submission

        resp = await c.get(f"/api/v1/verify/{known}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["mode"] == "hash"
        assert body["on_chain"]["exists"] is True

        unknown = "0x" + "22" * 32
        resp = await c.get(f"/api/v1/verify/{unknown}")
        body = resp.json()
        assert body["mode"] == "hash"
        assert body["on_chain"]["exists"] is False


@pytest.mark.asyncio
async def test_verify_detects_tampered_report(tmp_path):
    application = build_app(
        tmp_path,
        fetcher=StubFetcher(good_fetch_result()),
        registry_address="0xThreatRegistry",
    )
    application.state.registry_client = StubRegistryClient()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        # A suspicious URL: heuristics flag it, so the stored classification is
        # worse than low_risk and tampering it is a meaningful change.
        report = await create_report(c, url="http://paypa1.com.verify-account.xyz/")
        report_id = report["report_id"]
        assert report["classification"] != "low_risk"

        # Tamper with the stored report JSON directly in SQLite: forge a
        # favourable verdict.
        db_path = tmp_path / "api-test.db"
        conn = sqlite3.connect(str(db_path))
        stored = json.loads(
            conn.execute("SELECT report_json FROM reports WHERE id = ?", (report_id,)).fetchone()[0]
        )
        stored["classification"] = "low_risk"
        conn.execute(
            "UPDATE reports SET report_json = ? WHERE id = ?",
            (json.dumps(stored), report_id),
        )
        conn.commit()
        conn.close()

        resp = await c.get(f"/api/v1/verify/{report_id}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["integrity_match"] is False
        assert "modified after analysis" in body["note"]
        # The recomputed hash (of the tampered content) was never committed.
        assert body["on_chain"]["exists"] is False


@pytest.mark.asyncio
async def test_verify_unknown_report_404(tmp_path):
    application = build_app(tmp_path, registry_address="0xThreatRegistry")
    application.state.registry_client = StubRegistryClient()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        resp = await c.get("/api/v1/verify/nope")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_verify_chain_disabled_still_returns_hash(tmp_path):
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        report = await create_report(c)
        resp = await c.get(f"/api/v1/verify/{report['report_id']}")
        assert resp.status_code == 200
        body = resp.json()
        assert body["chain_enabled"] is False
        assert body["report_hash"] == "0x" + report["integrity"]["canonical_json_sha256"]
        assert body["on_chain"] is None
        assert "TRUSTLENS_REGISTRY_ADDRESS" in body["note"]


# ---- supplied-report verification: POST /api/v1/verify/report (task 9) ----------


@pytest.mark.asyncio
async def test_verify_supplied_report_matches(tmp_path):
    """A user pastes an exported report JSON: the recomputed hash matches the
    report's own integrity field and the on-chain commitment of that hash."""
    application = build_app(
        tmp_path,
        fetcher=StubFetcher(good_fetch_result()),
        registry_address="0xThreatRegistry",
    )
    application.state.registry_client = StubRegistryClient()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        report = await create_report(c)
        await c.post(f"/api/v1/reports/{report['report_id']}/commit")

        resp = await c.post("/api/v1/verify/report", json={
            "report": report,
            "expected_hash": "0x" + report["integrity"]["canonical_json_sha256"],
        })
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["mode"] == "supplied_report"
        assert body["integrity_match"] is True
        assert body["hash_match"] is True
        assert body["on_chain"]["exists"] is True
        assert body["recomputed_hash"] == "0x" + report["integrity"]["canonical_json_sha256"]


@pytest.mark.asyncio
async def test_verify_supplied_report_detects_alteration(tmp_path):
    application = build_app(
        tmp_path,
        fetcher=StubFetcher(good_fetch_result()),
        registry_address="0xThreatRegistry",
    )
    application.state.registry_client = StubRegistryClient()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        # a suspicious URL so the stored classification is meaningful to forge
        report = await create_report(c, url="http://paypa1.com/")
        assert report["classification"] != "low_risk"
        await c.post(f"/api/v1/reports/{report['report_id']}/commit")

        tampered = dict(report)
        tampered["classification"] = "low_risk"  # forged favourable verdict
        resp = await c.post("/api/v1/verify/report", json={"report": tampered})
        assert resp.status_code == 200
        body = resp.json()
        assert body["integrity_match"] is False
        assert "altered" in body["note"].lower()
        # the tampered contents' hash is not the committed one
        assert body["on_chain"]["exists"] is False


@pytest.mark.asyncio
async def test_verify_supplied_report_malformed_and_too_large(tmp_path):
    application = build_app(tmp_path)
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        # not report-shaped
        resp = await c.post("/api/v1/verify/report", json={"report": {"hello": "world"}})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == "invalid_report"

        # wrong types for schema fields
        resp2 = await c.post("/api/v1/verify/report", json={
            "report": {"report_id": 123, "raw_input": None, "coverage": "nope"},
        })
        assert resp2.status_code == 400

        # oversized payload
        huge = {"report": {"report_id": "a" * 32, "raw_input": "x" * 600_000,
                           "created_at": "2026-01-01T00:00:00+00:00",
                           "coverage": {"attempted": 1, "completed": 1}}}
        resp3 = await c.post("/api/v1/verify/report", json=huge)
        assert resp3.status_code == 400
        assert resp3.json()["error"]["code"] == "report_too_large"


@pytest.mark.asyncio
async def test_verify_supplied_report_missing_integrity_metadata(tmp_path):
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        report = await create_report(c)
        stripped = {k: v for k, v in report.items() if k != "integrity"}
        resp = await c.post("/api/v1/verify/report", json={"report": stripped})
        assert resp.status_code == 200
        body = resp.json()
        assert body["integrity_match"] is None  # nothing to compare against
        assert body["hash_match"] is None       # no expected hash supplied
        assert body["recomputed_hash"].startswith("0x")


@pytest.mark.asyncio
async def test_verify_supplied_report_unknown_hash_and_invalid_hash(tmp_path):
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        report = await create_report(c)

        # expected hash that does NOT match the contents
        resp = await c.post("/api/v1/verify/report", json={
            "report": report, "expected_hash": "0x" + "ee" * 32,
        })
        body = resp.json()
        assert body["hash_match"] is False
        assert body["integrity_match"] is True  # contents match their own integrity

        # malformed expected hash
        resp2 = await c.post("/api/v1/verify/report", json={
            "report": report, "expected_hash": "0x1234",
        })
        assert resp2.status_code == 400
        assert resp2.json()["error"]["code"] == "invalid_hash"


@pytest.mark.asyncio
async def test_verify_supplied_report_chain_disabled_still_hashes(tmp_path):
    application = build_app(tmp_path, fetcher=StubFetcher(good_fetch_result()))
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        report = await create_report(c)
        resp = await c.post("/api/v1/verify/report", json={"report": report})
        assert resp.status_code == 200
        body = resp.json()
        assert body["chain_enabled"] is False
        assert body["on_chain"] is None
        assert body["integrity_match"] is True


@pytest.mark.asyncio
async def test_verify_supplied_report_degrades_when_chain_node_unreachable(tmp_path):
    """Chain configured but the node is down: the contents/integrity comparison
    must still be returned (unlike the GET verify endpoints, which 502)."""
    application = build_app(
        tmp_path,
        fetcher=StubFetcher(good_fetch_result()),
        registry_address="0xThreatRegistry",
    )

    class _DeadNodeClient:
        def is_connected(self):
            return False

        def get_chain_id(self):
            raise RuntimeError("node down")

        def verify(self, report_hash):
            raise RuntimeError("node down")

        def submit(self, report_hash, category):
            raise RuntimeError("node down")

    application.state.registry_client = _DeadNodeClient()
    transport = httpx.ASGITransport(app=application)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as c:
        report = await create_report(c)
        resp = await c.post("/api/v1/verify/report", json={"report": report})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["integrity_match"] is True
        assert body["on_chain"] is None
        assert body["chain_node_unreachable"] is True
        assert "unreachable" in body["note"].lower()


# ---- bonus: Hardhat restart resilience (deployment-file refresh) ----


def _write_deployment(path, address):
    import json as _json
    path.write_text(_json.dumps({"address": address}), encoding="utf-8")


def test_recovered_contract_address_on_mtime_change(tmp_path):
    import os

    from app.web3.registry import RegistryClient

    dep = tmp_path / "deployment.json"
    old_address = "0x" + "aa" * 20
    new_address = "0x" + "bb" * 20
    _write_deployment(dep, old_address)

    client = RegistryClient("http://127.0.0.1:8545", old_address, "0x" + "11" * 32,
                            deployment_file=str(dep))
    # same file, same address -> no recovery
    assert client._recovered_contract_address() is None
    # redeploy to a new address + bump mtime (granularity-safe via os.utime)
    _write_deployment(dep, new_address)
    os.utime(dep, (time.time() + 5, time.time() + 5))
    assert client._recovered_contract_address() == new_address
    # unchanged afterwards
    assert client._recovered_contract_address() is None


def test_call_recovery_on_empty_code_response(tmp_path):
    """A '0x code' answer (node restart wiped the deployment) triggers a
    re-read of the deployment file and one retry at the fresh address."""
    from web3.exceptions import BadFunctionCallOutput

    from app.web3.registry import RegistryClient

    dep = tmp_path / "deployment.json"
    old_address = "0x" + "aa" * 20
    new_address = "0x" + "bb" * 20
    _write_deployment(dep, old_address)

    client = RegistryClient("http://127.0.0.1:8545", old_address, "0x" + "11" * 32,
                            deployment_file=str(dep))

    class FakeFunction:
        def __init__(self, behavior):
            self._behavior = behavior

        def call(self):
            return self._behavior()

    class FakeFunctions:
        def __init__(self, behavior):
            self._behavior = behavior

        def verify(self, report_hash):
            return FakeFunction(self._behavior)

    class FakeContract:
        def __init__(self, behavior):
            self.functions = FakeFunctions(behavior)

    fake_contract = FakeContract(lambda: (_ for _ in ()).throw(
        BadFunctionCallOutput("Could not decode contract function call verify return data b''")))

    client._contract = fake_contract
    # simulate _ensure(): rebuild ONLY when the contract binding was cleared
    def fake_ensure():
        if client._contract is None:
            client._contract = FakeContract(lambda: False)  # verify() answers a bool
    client._ensure = fake_ensure  # type: ignore[assignment]
    _write_deployment(dep, new_address)
    import os as _os
    _os.utime(dep, (time.time() + 5, time.time() + 5))

    result = client.verify(b"\x11" * 32)
    assert result == {"exists": False}
    assert client._address == new_address  # rebound to the fresh deployment


def test_call_without_deployment_file_does_not_recover():
    from web3.exceptions import BadFunctionCallOutput

    from app.web3.registry import RegistryClient

    client = RegistryClient("http://127.0.0.1:8545", "0x" + "aa" * 20, "0x" + "11" * 32)

    class FakeFunction:
        def call(self):
            raise BadFunctionCallOutput("return data b''")

    class FakeFunctions:
        def verify(self, report_hash):
            return FakeFunction()

    class FakeContract:
        def __init__(self):
            self.functions = FakeFunctions()

    client._contract = FakeContract()
    client._ensure = lambda: None  # keep the fake binding; no real Web3 in tests
    with pytest.raises(BadFunctionCallOutput):
        client.verify(b"\x11" * 32)  # no deployment file -> no recovery path


def test_is_empty_code_error_classification():
    from web3.exceptions import BadFunctionCallOutput

    from app.web3.registry import RegistryClient

    assert RegistryClient._is_empty_code_error(BadFunctionCallOutput("return data b''")) is True
    assert RegistryClient._is_empty_code_error(RuntimeError("connection refused")) is False
