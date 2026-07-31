from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta
from pathlib import Path

import httpx
import pytest

from sub2api_recorder.app import create_app
from sub2api_recorder.security import fingerprint_token
from sub2api_recorder.storage import RequestMetadata
from sub2api_recorder.token_resolver import TokenResolution


def _proxy_headers(settings) -> dict[str, str]:
    return {"X-Audit-Proxy-Secret": settings.proxy_secret}


def _user_headers(settings, username: str = "auditor") -> dict[str, str]:
    return {
        **_proxy_headers(settings),
        "X-authentik-username": username,
    }


async def _ingest_owned_record(
    app,
    settings,
    tmp_path: Path,
    username: str | None,
):
    label = username or "unowned"
    body = {"model": f"model-{label}", "input": [f"body-{label}"]}
    raw = json.dumps(body, separators=(",", ":")).encode()
    path = tmp_path / f"{label}.json"
    path.write_bytes(raw)
    token = None
    resolution = TokenResolution("no_token")
    if username is not None:
        token = fingerprint_token(
            f"sk-test-{username}-1234",
            "authorization",
            settings.token_hmac_key,
        )
        resolution = TokenResolution(
            "resolved",
            api_key_id=len(username),
            user_id=len(username) + 100,
            key_name=f"key-{username}",
            username=username,
        )
    metadata = RequestMetadata(
        occurred_at=datetime.now(settings.timezone),
        method="POST",
        uri=f"/v1/{label}",
        client_ip="192.0.2.10",
        user_agent="pytest",
        content_type="application/json",
        body_size=len(raw),
        body_sha256=hashlib.sha256(raw).hexdigest(),
    )
    result = await app.state.storage.ingest(path, metadata, token, resolution)
    path.unlink()
    return result, body


@pytest.mark.asyncio
async def test_auth_ingest_and_readonly_ui(settings) -> None:
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            assert (await client.get("/audit/")).status_code == 403
            assert (await client.get("/admin/audit/")).status_code == 403
            assert (
                await client.get(
                    "/admin/audit/", headers=_proxy_headers(settings)
                )
            ).status_code == 401
            assert (
                await client.get(
                    "/admin/audit/",
                    headers=_user_headers(settings, "intruder"),
                )
            ).status_code == 403
            personal_page = await client.get(
                "/audit/",
                headers=_user_headers(settings, "intruder"),
            )
            assert personal_page.status_code == 200
            page = await client.get(
                "/admin/audit/", headers=_user_headers(settings)
            )
            assert page.status_code == 200
            assert page.headers["cache-control"] == "no-store"
            assert page.headers["x-frame-options"] == "SAMEORIGIN"
            content_security_policy = page.headers["content-security-policy"]
            assert "default-src 'self'" in content_security_policy
            assert "frame-ancestors 'self'" in content_security_policy

            context = await client.get(
                "/admin/audit/api/context",
                headers=_user_headers(settings),
            )
            assert context.status_code == 200
            context_payload = context.json()
            assert context_payload["timezone"] == "Asia/Hong_Kong"
            assert context_payload["viewer"] == {
                "username": "auditor",
                "can_view_all": True,
                "scope": "all",
                "audit_enabled": False,
            }
            service_now = datetime.fromisoformat(context_payload["now"])
            assert service_now.utcoffset() == timedelta(hours=8)

            body = {
                "model": "gpt-test",
                "input": [
                    {
                        "role": "user",
                        "content": [
                            {
                                "type": "text",
                                "text": "<script>x</script>",
                            }
                        ],
                    }
                ],
            }
            headers = {
                **_proxy_headers(settings),
                "X-Audit-Original-Method": "POST",
                "X-Audit-Original-URI": "/v1/responses?x=1",
                "Authorization": "Bearer sk-do-not-store-9999",
            }
            app.state.resolver.resolve = lambda token, fingerprint: TokenResolution(
                "resolved",
                api_key_id=1,
                user_id=2,
                key_name="auditor-key",
                username="auditor",
            )

            preference = await client.get(
                "/audit/api/preference",
                headers=_user_headers(settings),
            )
            assert preference.json() == {
                "enabled": False,
                "default_enabled": False,
                "updated_at": None,
            }
            skipped = await client.post(
                "/_audit_ingest",
                headers=headers,
                json=body,
            )
            assert skipped.status_code == 204
            assert not list(settings.temp_dir.glob("ingest-*"))
            empty_listing = await client.get(
                "/admin/audit/api/requests",
                headers=_user_headers(settings),
            )
            assert empty_listing.json()["items"] == []

            enabled = await client.put(
                "/audit/api/preference",
                headers=_user_headers(settings),
                json={"enabled": True},
            )
            assert enabled.status_code == 200
            assert enabled.json()["enabled"] is True
            recorded = await client.post(
                "/_audit_ingest", headers=headers, json=body
            )
            assert recorded.status_code == 204

            listing = await client.get(
                "/admin/audit/api/requests", headers=_user_headers(settings)
            )
            assert listing.status_code == 200
            item = listing.json()["items"][0]
            assert item["token_masked"] == "…9999"
            detail = await client.get(
                f"/admin/audit/api/requests/{item['month']}/{item['id']}",
                headers=_user_headers(settings),
            )
            assert detail.status_code == 200
            assert detail.json()["body"] == body
            assert detail.json()["body_view"] == "full"

            compact_detail = await client.get(
                f"/admin/audit/api/requests/{item['month']}/{item['id']}",
                params={"view": "compact"},
                headers=_user_headers(settings),
            )
            assert compact_detail.status_code == 200
            compact_payload = compact_detail.json()
            assert compact_payload["body_view"] == "compact"
            assert compact_payload["body"]["model"] == "gpt-test"
            assert compact_payload["body"]["_audit_view"]["mode"] == "compact"

            personal_context = await client.get(
                "/audit/api/context",
                headers=_user_headers(settings),
            )
            assert personal_context.json()["viewer"] == {
                "username": "auditor",
                "can_view_all": False,
                "scope": "personal",
                "audit_enabled": True,
            }
            personal_listing = await client.get(
                "/audit/api/requests",
                headers=_user_headers(settings),
            )
            assert len(personal_listing.json()["items"]) == 1

            disabled = await client.put(
                "/audit/api/preference",
                headers=_user_headers(settings),
                json={"enabled": False},
            )
            assert disabled.status_code == 200
            assert disabled.json()["enabled"] is False
            skipped_after_disable = await client.post(
                "/_audit_ingest",
                headers={**headers, "X-Audit-Original-URI": "/v1/after-disable"},
                json={"model": "not-recorded"},
            )
            assert skipped_after_disable.status_code == 204
            retained_listing = await client.get(
                "/audit/api/requests",
                headers=_user_headers(settings),
            )
            assert len(retained_listing.json()["items"]) == 1


@pytest.mark.asyncio
async def test_personal_scope_is_enforced_for_lists_details_and_cache(
    settings,
    tmp_path: Path,
) -> None:
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        alice, alice_body = await _ingest_owned_record(
            app, settings, tmp_path, "alice"
        )
        bob, bob_body = await _ingest_owned_record(app, settings, tmp_path, "bob")
        await _ingest_owned_record(app, settings, tmp_path, None)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://test",
        ) as client:
            alice_headers = _user_headers(settings, "alice")
            bob_headers = _user_headers(settings, "bob")
            admin_headers = _user_headers(settings)

            assert (
                await client.get("/admin/audit/", headers=alice_headers)
            ).status_code == 403

            alice_listing = await client.get(
                "/audit/api/requests",
                params={"username": "bob"},
                headers=alice_headers,
            )
            assert alice_listing.status_code == 200
            assert [item["username"] for item in alice_listing.json()["items"]] == [
                "alice"
            ]

            admin_listing = await client.get(
                "/admin/audit/api/requests",
                headers=admin_headers,
            )
            assert len(admin_listing.json()["items"]) == 3
            admin_bob_listing = await client.get(
                "/admin/audit/api/requests",
                params={"username": "bob"},
                headers=admin_headers,
            )
            assert [item["username"] for item in admin_bob_listing.json()["items"]] == [
                "bob"
            ]

            bob_url = f"/admin/audit/api/requests/{bob.month}/{bob.request_id}"
            warmed = await client.get(bob_url, headers=admin_headers)
            assert warmed.status_code == 200
            assert warmed.json()["body"] == bob_body

            hidden_bob = await client.get(
                f"/audit/api/requests/{bob.month}/{bob.request_id}",
                headers=alice_headers,
            )
            assert hidden_bob.status_code == 404
            own_alice = await client.get(
                f"/audit/api/requests/{alice.month}/{alice.request_id}",
                headers=alice_headers,
            )
            assert own_alice.status_code == 200
            assert own_alice.json()["body"] == alice_body
            own_bob = await client.get(
                f"/audit/api/requests/{bob.month}/{bob.request_id}",
                headers=bob_headers,
            )
            assert own_bob.status_code == 200
            assert own_bob.json()["body"] == bob_body

            alice_months = await client.get(
                "/audit/api/months",
                headers=alice_headers,
            )
            assert alice_months.status_code == 200
            assert alice_months.json()["items"] == [
                {
                    "month": alice.month,
                    "current": True,
                    "records": 1,
                    "size_bytes": None,
                    "schema_version": 1,
                    "archive": None,
                }
            ]
            no_record_months = await client.get(
                "/audit/api/months",
                headers=_user_headers(settings, "charlie"),
            )
            assert no_record_months.json()["items"] == []


@pytest.mark.asyncio
async def test_query_range_limit_and_ingest_limit(settings) -> None:
    app = create_app(settings)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://test"
        ) as client:
            now = datetime.now(settings.timezone)
            too_early = now - timedelta(days=91)
            response = await client.get(
                "/admin/audit/api/requests",
                params={"start": too_early.isoformat(), "end": now.isoformat()},
                headers=_user_headers(settings),
            )
            assert response.status_code == 400

            app.state.resolver.resolve = lambda token, fingerprint: TokenResolution(
                "resolved",
                api_key_id=1,
                user_id=2,
                key_name="auditor-key",
                username="auditor",
            )
            preference = await client.put(
                "/audit/api/preference",
                headers=_user_headers(settings),
                json={"enabled": True},
            )
            assert preference.status_code == 200
            too_big = b"x" * (settings.max_body_bytes + 1)
            response = await client.post(
                "/_audit_ingest",
                content=too_big,
                headers={
                    **_proxy_headers(settings),
                    "X-Audit-Original-URI": "/v1/test",
                    "Content-Type": "application/octet-stream",
                    "Authorization": "Bearer sk-size-test-1234",
                },
            )
            assert response.status_code == 413
