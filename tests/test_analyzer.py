from src.analyzer import analyze_incident, analyze_manifest


def test_detects_kubernetes_crashloop_and_escalates_for_production() -> None:
    result = analyze_incident(
        alert_text="Production checkout outage after deploy",
        logs_text="""
        CrashLoopBackOff
        Back-off restarting failed container
        Liveness probe failed
        Exit Code: 137
        """,
    )

    assert result["incident_type"] == "Kubernetes CrashLoopBackOff"
    assert result["severity"] == "critical"
    assert any("roll back" in action.lower() or "rollback" in action.lower() for action in result["recommended_actions"])


def test_manifest_review_finds_high_value_kubernetes_issues() -> None:
    findings = analyze_manifest(
        """
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: checkout-api
        spec:
          replicas: 1
          template:
            spec:
              containers:
                - name: api
                  image: ghcr.io/acme/checkout-api:latest
                  env:
                    - name: DATABASE_PASSWORD
                      value: plaintext
        """
    )

    titles = [finding["title"] for finding in findings]
    assert any("floating image tag" in title.lower() for title in titles)
    assert any("missing resource guardrails" in title.lower() for title in titles)
    assert any("secret exposed as plain text" in title.lower() for title in titles)


def test_ci_credential_failure_is_classified_cleanly() -> None:
    result = analyze_incident(
        alert_text="Deploy pipeline failed for production release",
        logs_text="""
        Run docker/login-action@v3
        denied: requested access to the resource is denied
        AccessDenied: User is not authorized to perform sts:AssumeRole
        Error: Process completed with exit code 1.
        """,
    )

    assert result["incident_type"] == "CI/CD Credential or Registry Failure"
    assert result["severity"] == "critical"
    assert any("preflight identity check" in action.lower() for action in result["recommended_actions"])
