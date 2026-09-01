from datetime import datetime, timedelta

from threat_intelligence.models import IOC, IOCStatus, IOCType
from threat_intelligence.store import LocalIOCStore


def test_add_and_lookup_ioc() -> None:
    store = LocalIOCStore()

    ioc = IOC(
        value="203.0.113.10",
        ioc_type=IOCType.IP,
        status=IOCStatus.MALICIOUS,
        source="test-feed",
        confidence=95,
    )

    store.add_ioc(ioc)

    result = store.lookup_ioc(
        "203.0.113.10",
        IOCType.IP,
    )

    assert result == ioc


def test_unknown_ioc_returns_none() -> None:
    store = LocalIOCStore()

    result = store.lookup_ioc(
        "unknown.example",
        IOCType.DOMAIN,
    )

    assert result is None


def test_ioc_types_are_distinct() -> None:
    store = LocalIOCStore()

    ip_ioc = IOC(
        value="example",
        ioc_type=IOCType.IP,
        status=IOCStatus.SAFE,
    )

    domain_ioc = IOC(
        value="example",
        ioc_type=IOCType.DOMAIN,
        status=IOCStatus.SUSPICIOUS,
    )

    store.add_ioc(ip_ioc)
    store.add_ioc(domain_ioc)

    assert store.lookup_ioc(
        "example",
        IOCType.IP,
    ) == ip_ioc

    assert store.lookup_ioc(
        "example",
        IOCType.DOMAIN,
    ) == domain_ioc


def test_remove_ioc() -> None:
    store = LocalIOCStore()

    ioc = IOC(
        value="bad.example",
        ioc_type=IOCType.DOMAIN,
        status=IOCStatus.MALICIOUS,
    )

    store.add_ioc(ioc)

    assert store.remove_ioc(
        "bad.example",
        IOCType.DOMAIN,
    ) is True

    assert store.lookup_ioc(
        "bad.example",
        IOCType.DOMAIN,
    ) is None


def test_remove_missing_ioc_returns_false() -> None:
    store = LocalIOCStore()

    assert store.remove_ioc(
        "missing.example",
        IOCType.DOMAIN,
    ) is False


def test_expiration_metadata_is_preserved() -> None:
    now = datetime.utcnow()

    ioc = IOC(
        value="expired.example",
        ioc_type=IOCType.DOMAIN,
        status=IOCStatus.MALICIOUS,
        first_seen=now - timedelta(days=10),
        last_seen=now - timedelta(days=2),
        expires_at=now - timedelta(days=1),
    )

    store = LocalIOCStore()
    store.add_ioc(ioc)

    result = store.lookup_ioc(
        "expired.example",
        IOCType.DOMAIN,
    )

    assert result == ioc
    assert result is not None
    assert result.is_expired(now) is True


def test_ioc_lookup_normalizes_value() -> None:
    store = LocalIOCStore()

    ioc = IOC(
        value="Bad.Example",
        ioc_type=IOCType.DOMAIN,
        status=IOCStatus.MALICIOUS,
    )

    store.add_ioc(ioc)

    result = store.lookup_ioc(
        "  bad.example  ",
        IOCType.DOMAIN,
    )

    assert result is not None
    assert result.value == "bad.example"


def test_expired_ioc_is_not_returned_by_active_lookup() -> None:
    now = datetime.utcnow()

    ioc = IOC(
        value="expired.example",
        ioc_type=IOCType.DOMAIN,
        status=IOCStatus.MALICIOUS,
        expires_at=now - timedelta(minutes=1),
    )

    store = LocalIOCStore()
    store.add_ioc(ioc)

    result = store.lookup_active_ioc(
        "expired.example",
        IOCType.DOMAIN,
        now=now,
    )

    assert result is None


def test_active_ioc_is_returned_by_active_lookup() -> None:
    now = datetime.utcnow()

    ioc = IOC(
        value="active.example",
        ioc_type=IOCType.DOMAIN,
        status=IOCStatus.SUSPICIOUS,
        expires_at=now + timedelta(hours=1),
    )

    store = LocalIOCStore()
    store.add_ioc(ioc)

    result = store.lookup_active_ioc(
        "active.example",
        IOCType.DOMAIN,
        now=now,
    )

    assert result == ioc


def test_get_ioc_status_returns_status() -> None:
    store = LocalIOCStore()

    ioc = IOC(
        value="malicious.example",
        ioc_type=IOCType.DOMAIN,
        status=IOCStatus.MALICIOUS,
    )

    store.add_ioc(ioc)

    assert store.get_ioc_status(
        "malicious.example",
        IOCType.DOMAIN,
    ) == IOCStatus.MALICIOUS


def test_get_ioc_status_returns_none_for_unknown_ioc() -> None:
    store = LocalIOCStore()

    assert store.get_ioc_status(
        "unknown.example",
        IOCType.DOMAIN,
    ) is None


def test_get_ioc_status_returns_none_for_expired_ioc() -> None:
    now = datetime.utcnow()

    ioc = IOC(
        value="expired.example",
        ioc_type=IOCType.DOMAIN,
        status=IOCStatus.MALICIOUS,
        expires_at=now - timedelta(minutes=1),
    )

    store = LocalIOCStore()
    store.add_ioc(ioc)

    assert store.get_ioc_status(
        "expired.example",
        IOCType.DOMAIN,
        now=now,
    ) is None