from __future__ import annotations

from sub2api_recorder.preferences import AuditPreferenceStore


def test_audit_preferences_default_off_and_persist(settings) -> None:
    store = AuditPreferenceStore(
        settings.data_dir,
        settings.sqlite_busy_timeout_ms,
        settings.timezone,
    )
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    store.start()
    assert store.get("alice").enabled is False
    assert store.get("alice").updated_at is None
    enabled = store.set_enabled("alice", True)
    assert enabled.enabled is True
    assert enabled.updated_at is not None
    assert store.is_enabled("alice") is True
    assert store.is_enabled("bob") is False
    assert store.health()["enabled_users"] == 1
    store.close()

    reopened = AuditPreferenceStore(
        settings.data_dir,
        settings.sqlite_busy_timeout_ms,
        settings.timezone,
    )
    reopened.start()
    assert reopened.is_enabled("alice") is True
    reopened.set_enabled("alice", False)
    assert reopened.is_enabled("alice") is False
    reopened.close()
