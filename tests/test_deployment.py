from pathlib import Path


def test_nginx_example_uses_exact_internal_location_and_safe_log_format() -> None:
    text = Path("deploy/nginx-sub2api-audit.conf").read_text(encoding="utf-8")
    assert "mirror /_audit_ingest;" in text
    assert "location = /_audit_ingest" in text
    assert "proxy_pass_request_body on;" in text
    assert "X-Audit-Original-URI $request_uri" in text
    assert "location = /admin/audit" in text
    assert "location ^~ /admin/audit/" in text
    assert "location = /audit" in text
    assert "location ^~ /audit/" in text
    assert "access_log /config/log/nginx/sub2api_access.log combined;" in text


def test_compose_binds_only_loopback_and_one_worker() -> None:
    compose = Path("docker-compose.yaml").read_text(encoding="utf-8")
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    assert '"127.0.0.1:9203:8080"' in compose
    assert "sub2api_default" in compose
    assert '"--workers", "1"' in dockerfile
    assert '"--no-access-log"' in dockerfile
