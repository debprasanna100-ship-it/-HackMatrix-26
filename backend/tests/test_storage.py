"""Storage layer tests: schema creation, save/get/list roundtrip."""
from __future__ import annotations

import pytest

from app.storage import repository
from app.storage.database import ReportRow, init_engine


@pytest.fixture
def db(tmp_path, monkeypatch):
    """Fresh engine per test via a module reload-free reset."""
    import app.storage.database as dbmod

    monkeypatch.setattr(dbmod, "_engine", None)
    monkeypatch.setattr(dbmod, "_SessionLocal", None)
    from app.config import Settings

    settings = Settings(database_url=f"sqlite:///{tmp_path.as_posix()}/storage-test.db")
    init_engine(settings)
    return dbmod


def _payload(report_id: str) -> dict:
    return {
        "report_id": report_id,
        "created_at": "2026-11-07T12:00:00+00:00",
        "input_type": "url",
        "raw_input": "example.com",
        "normalized": {"url": "https://example.com/", "registrable_domain": "example.com"},
        "classification": "inconclusive",
        "findings": [{"id": "X-1"}, {"id": "X-2"}],
    }


def test_save_and_get(db):
    pid = repository.save_report(_payload("a" * 32))
    assert pid == "a" * 32
    stored = repository.get_report(pid)
    assert stored is not None
    assert stored["report_id"] == "a" * 32
    assert stored["normalized"]["registrable_domain"] == "example.com"
    assert len(stored["findings"]) == 2


def test_get_missing_returns_none(db):
    assert repository.get_report("f" * 32) is None


def test_list_reports(db):
    repository.save_report(_payload("b" * 32))
    repository.save_report(_payload("c" * 32))
    listing = repository.list_reports(limit=10)
    assert listing["count"] == 2
    ids = {r["report_id"] for r in listing["reports"]}
    assert ids == {"b" * 32, "c" * 32}
    summary = listing["reports"][0]
    assert summary["findings_count"] == 2
    assert summary["registrable_domain"] == "example.com"


def test_save_is_idempotent_on_same_id(db):
    repository.save_report(_payload("d" * 32))
    repository.save_report(_payload("d" * 32))  # merge, not insert
    listing = repository.list_reports()
    assert listing["count"] == 1


# ---- deletion / retention (privacy policy) ------------------------------------------


def test_delete_report_removes_dependents(db):
    from app.storage.database import ChainCommitmentRow, CorrelationIndicatorRow

    pid = "e" * 32
    repository.save_report(_payload(pid))
    with db.session() as s:
        s.add(CorrelationIndicatorRow(kind="domain", value="example.com", report_id=pid,
                                      classification="low_risk"))
        s.add(ChainCommitmentRow(report_id=pid, report_hash="0x" + "ab" * 32, tx_hash="0x" + "cd" * 32,
                                 contract_address="0x" + "ee" * 20, chain_id=31337, block_number=1))
        s.commit()

    assert repository.delete_report(pid) is True
    assert repository.get_report(pid) is None
    with db.session() as s:
        assert s.query(CorrelationIndicatorRow).filter_by(report_id=pid).count() == 0
        assert s.query(ChainCommitmentRow).filter_by(report_id=pid).count() == 0
    # idempotence
    assert repository.delete_report(pid) is False


def test_purge_reports_older_than(db):
    old = _payload("f" * 32)
    old["created_at"] = "2020-01-01T00:00:00+00:00"
    recent = _payload("0" * 32)
    repository.save_report(old)
    repository.save_report(recent)

    removed = repository.purge_reports_older_than(30)
    assert removed == 1
    assert repository.get_report("f" * 32) is None
    assert repository.get_report("0" * 32) is not None
    # zero/negative retention is a no-op
    repository.save_report(_payload("1" * 32))
    assert repository.purge_reports_older_than(0) == 0
    assert repository.get_report("1" * 32) is not None
