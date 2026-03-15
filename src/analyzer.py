from __future__ import annotations

import re
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - handled at runtime when dependency is missing
    yaml = None


SEVERITY_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

SECRET_NAME_HINTS = ("secret", "token", "password", "passwd", "key")
PRODUCTION_HINTS = (
    r"\bprod\b",
    r"\bproduction\b",
    r"\bcustomer\b",
    r"\boutage\b",
    r"\bsev[- ]?1\b",
    r"\bp1\b",
)

INCIDENT_RULES = [
    {
        "incident_type": "Kubernetes CrashLoopBackOff",
        "domain": "runtime",
        "severity": "high",
        "patterns": [
            r"crashloopbackoff",
            r"back-off restarting failed container",
            r"container .*? restarting",
            r"restart count",
        ],
        "signal": "Pods are continuously restarting after deployment.",
        "summary": "The application is failing during startup or immediately after the health check window.",
        "causes": [
            "Broken startup configuration or missing environment variables",
            "Application boot failure after a recent deployment",
            "Liveness or startup probe firing before the service is ready",
        ],
        "actions": [
            "Inspect the first failing container logs and compare them with the last healthy release.",
            "Validate secrets, config maps, and required dependency endpoints before restarting pods again.",
            "If this started right after a rollout, pause or roll back the deployment to reduce blast radius.",
        ],
        "automation": [
            "Trigger a rollback recommendation when restart count spikes after a fresh deployment.",
            "Attach the last successful release metadata to incident alerts automatically.",
        ],
    },
    {
        "incident_type": "Container Image Pull Failure",
        "domain": "delivery",
        "severity": "high",
        "patterns": [
            r"imagepullbackoff",
            r"errimagepull",
            r"pull access denied",
            r"authentication required",
            r"requested access to the resource is denied",
        ],
        "signal": "Workers cannot pull the container image from the registry.",
        "summary": "The deployment is blocked by image tag, registry, or authentication issues.",
        "causes": [
            "Image tag does not exist in the container registry",
            "Registry credentials or workload identity permissions are invalid",
            "The deployment is referencing `latest` and picked up an unexpected image",
        ],
        "actions": [
            "Verify the image tag exists and was pushed successfully by the build pipeline.",
            "Check image pull secrets, registry permissions, and workload identity bindings.",
            "Pin the deployment to an immutable release tag before retrying.",
        ],
        "automation": [
            "Fail the release early when the deployment manifest references a floating image tag.",
            "Validate registry access in CI before promotion to production.",
        ],
    },
    {
        "incident_type": "Resource Pressure or OOM Kill",
        "domain": "capacity",
        "severity": "high",
        "patterns": [
            r"oomkilled",
            r"exit code 137",
            r"out of memory",
            r"memory cgroup",
            r"cpu throttling",
            r"insufficient memory",
        ],
        "signal": "The workload is being terminated or throttled because of resource pressure.",
        "summary": "The service likely needs better sizing, safer limits, or workload-specific scaling rules.",
        "causes": [
            "Container memory limits are too low for startup or peak traffic",
            "Resource requests are missing, causing poor scheduling decisions",
            "A recent code path increased memory or CPU demand unexpectedly",
        ],
        "actions": [
            "Compare current memory and CPU usage with requests and limits before the next rollout.",
            "Add resource requests and limits to every container in the workload.",
            "Review HPA behavior or vertical sizing if this coincides with traffic growth.",
        ],
        "automation": [
            "Block deployment manifests that omit requests and limits.",
            "Alert on sustained restart loops plus memory pressure instead of treating them separately.",
        ],
    },
    {
        "incident_type": "Probe or Health Check Failure",
        "domain": "reliability",
        "severity": "medium",
        "patterns": [
            r"readiness probe failed",
            r"liveness probe failed",
            r"startup probe failed",
            r"connection refused",
            r"health check",
        ],
        "signal": "Health checks are failing before the service can serve traffic reliably.",
        "summary": "Probe timing, endpoint wiring, or startup latency are likely misconfigured.",
        "causes": [
            "Readiness or liveness probes are pointing to the wrong port or path",
            "The service needs a longer startup window than the probe allows",
            "A dependency outage is making the service appear unhealthy",
        ],
        "actions": [
            "Check probe path, port, and initial delay against the service startup profile.",
            "Separate readiness from liveness so dependency warmup does not trigger restarts.",
            "Confirm the application binds to the port exposed in the manifest.",
        ],
        "automation": [
            "Add a policy check that blocks workloads without readiness and liveness probes.",
            "Capture probe failures and rollout metadata in the same incident payload.",
        ],
    },
    {
        "incident_type": "Network or Dependency Outage",
        "domain": "network",
        "severity": "high",
        "patterns": [
            r"dial tcp",
            r"i/o timeout",
            r"no such host",
            r"temporary failure in name resolution",
            r"upstream connect error",
            r"tls handshake timeout",
        ],
        "signal": "The service cannot reach a required dependency or endpoint.",
        "summary": "The failure is likely upstream of the app itself and tied to DNS, network, or service connectivity.",
        "causes": [
            "DNS or service discovery is returning an invalid target",
            "Network policy, security group, or firewall rules changed recently",
            "A downstream dependency is degraded or unreachable",
        ],
        "actions": [
            "Test connectivity from a running pod or runner in the same network zone.",
            "Review recent network policy, ingress, service mesh, or firewall changes.",
            "Check downstream dependency status before continuing with redeploys.",
        ],
        "automation": [
            "Enrich alerts with dependency ownership metadata to shorten handoff time.",
            "Run synthetic dependency checks after every production deployment.",
        ],
    },
    {
        "incident_type": "CI Test or Build Failure",
        "domain": "cicd",
        "severity": "medium",
        "patterns": [
            r"process completed with exit code 1",
            r"tests failed",
            r"assertionerror",
            r"pytest .*? failed",
            r"npm err!",
            r"compilation failed",
        ],
        "signal": "The pipeline is failing during the build or test stage.",
        "summary": "The deployment is blocked by code quality, dependency, or packaging issues in CI.",
        "causes": [
            "A test regression or missing dependency is breaking the pipeline",
            "Build scripts changed without corresponding runner updates",
            "The artifact packaging step is incompatible with the current branch changes",
        ],
        "actions": [
            "Identify the first failing step and compare it with the previous green run.",
            "Pin tool versions used in CI so the build environment is reproducible.",
            "Split unit test failures from packaging failures to shorten triage time.",
        ],
        "automation": [
            "Auto-label failures by stage and ownership so the right team is paged first.",
            "Publish a short triage summary directly into pull request comments.",
        ],
    },
    {
        "incident_type": "CI/CD Credential or Registry Failure",
        "domain": "cicd",
        "severity": "high",
        "patterns": [
            r"accessdenied",
            r"not authorized to perform",
            r"permission denied",
            r"unauthorized",
            r"failed to assume role",
            r"docker/login-action",
        ],
        "signal": "The pipeline cannot authenticate to a registry, cloud account, or deployment target.",
        "summary": "The release path is blocked by expired credentials, IAM policy drift, or secret rotation issues.",
        "causes": [
            "Cloud IAM permissions changed and the runner can no longer assume the deploy role",
            "Registry credentials or tokens were rotated without updating CI secrets",
            "OIDC or workload identity trust settings no longer match the pipeline configuration",
        ],
        "actions": [
            "Compare current CI credentials and IAM trust policy with the last successful release.",
            "Rotate the failing secret or token intentionally and validate the new scope.",
            "Add a preflight identity check before the deploy or publish stage runs.",
        ],
        "automation": [
            "Run a permissions smoke test before pushing images or applying infrastructure.",
            "Detect secret age and pending expiration so credential failures are prevented earlier.",
        ],
    },
]


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip().lower())


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item and item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def analyze_manifest(manifest_text: str) -> list[dict[str, str]]:
    if not manifest_text.strip():
        return []

    if yaml is None:
        return [
            {
                "severity": "medium",
                "title": "Manifest review skipped",
                "detail": "Install `pyyaml` to enable Kubernetes manifest checks.",
            }
        ]

    findings: list[dict[str, str]] = []

    try:
        documents = [
            document for document in yaml.safe_load_all(manifest_text) if isinstance(document, dict)
        ]
    except yaml.YAMLError as exc:
        return [
            {
                "severity": "medium",
                "title": "Manifest parsing issue",
                "detail": f"YAML could not be parsed cleanly: {exc}",
            }
        ]

    for document in documents:
        kind = str(document.get("kind", "Resource"))
        metadata = document.get("metadata") or {}
        name = metadata.get("name", kind.lower())
        spec = document.get("spec") or {}
        pod_spec = (
            spec.get("template", {}).get("spec")
            or spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec")
            or spec.get("spec")
            or {}
        )
        containers = pod_spec.get("containers") or []

        if kind in {"Deployment", "StatefulSet"}:
            replicas = spec.get("replicas")
            if replicas is None or replicas < 2:
                findings.append(
                    {
                        "severity": "medium",
                        "title": f"{name}: limited replica redundancy",
                        "detail": "Production-facing workloads should usually run at least 2 replicas to reduce rollout and node failure risk.",
                    }
                )

        for container in containers:
            container_name = container.get("name", "container")
            image = str(container.get("image", ""))
            resources = container.get("resources") or {}

            if not image or ":" not in image or image.endswith(":latest"):
                findings.append(
                    {
                        "severity": "high",
                        "title": f"{container_name}: floating image tag",
                        "detail": "Pin the image to an immutable version tag instead of `latest` to make rollbacks and incident correlation safer.",
                    }
                )

            if not resources.get("requests") or not resources.get("limits"):
                findings.append(
                    {
                        "severity": "high",
                        "title": f"{container_name}: missing resource guardrails",
                        "detail": "Add CPU and memory requests plus limits so the scheduler and autoscaling signals are meaningful.",
                    }
                )

            if container.get("readinessProbe") is None:
                findings.append(
                    {
                        "severity": "medium",
                        "title": f"{container_name}: readiness probe missing",
                        "detail": "Without readiness checks, traffic can be routed to a pod before it is truly ready.",
                    }
                )

            if container.get("livenessProbe") is None:
                findings.append(
                    {
                        "severity": "medium",
                        "title": f"{container_name}: liveness probe missing",
                        "detail": "Liveness probes help the platform recover stuck containers automatically.",
                    }
                )

            for env_var in container.get("env") or []:
                env_name = str(env_var.get("name", ""))
                lowered_name = env_name.lower()
                if any(hint in lowered_name for hint in SECRET_NAME_HINTS):
                    if "value" in env_var and "valueFrom" not in env_var:
                        findings.append(
                            {
                                "severity": "high",
                                "title": f"{container_name}: secret exposed as plain text",
                                "detail": f"`{env_name}` is hard-coded in the manifest. Move it to a secret reference instead.",
                            }
                        )

    return findings


def _rank_incidents(combined_text: str) -> list[dict[str, Any]]:
    ranked: list[dict[str, Any]] = []
    for rule in INCIDENT_RULES:
        matches = [pattern for pattern in rule["patterns"] if re.search(pattern, combined_text)]
        if matches:
            ranked.append(
                {
                    **rule,
                    "match_count": len(matches),
                }
            )

    ranked.sort(
        key=lambda item: (
            SEVERITY_RANK[item["severity"]],
            item["match_count"],
        ),
        reverse=True,
    )
    return ranked


def _derive_severity(base_severity: str, combined_text: str, manifest_findings: list[dict[str, str]]) -> str:
    severity = base_severity

    if any(re.search(pattern, combined_text) for pattern in PRODUCTION_HINTS):
        if severity == "medium":
            severity = "high"
        elif severity == "high":
            severity = "critical"

    if any(finding["severity"] == "high" for finding in manifest_findings) and severity == "medium":
        severity = "high"

    return severity


def _build_timeline(
    alert_text: str,
    primary_incident: dict[str, Any],
    change_text: str,
    manifest_findings: list[dict[str, str]],
) -> list[dict[str, str]]:
    alert_excerpt = alert_text.strip()[:180] or "Incident context came mostly from logs and diagnostics."
    timeline = [
        {
            "label": "Current signal",
            "detail": alert_excerpt,
        },
        {
            "label": "Primary diagnosis",
            "detail": primary_incident["signal"],
        },
    ]

    if change_text.strip():
        timeline.append(
            {
                "label": "Recent change correlation",
                "detail": change_text.strip()[:180],
            }
        )

    if manifest_findings:
        timeline.append(
            {
                "label": "Hardening gap",
                "detail": manifest_findings[0]["title"],
            }
        )

    return timeline


def analyze_incident(
    alert_text: str,
    logs_text: str,
    manifest_text: str = "",
    change_text: str = "",
) -> dict[str, Any]:
    if not (alert_text.strip() or logs_text.strip() or manifest_text.strip()):
        raise ValueError("Provide incident context, logs, or a manifest to analyze.")

    combined_text = _normalize_text("\n".join([alert_text, logs_text, manifest_text, change_text]))
    manifest_findings = analyze_manifest(manifest_text)
    ranked_incidents = _rank_incidents(combined_text)

    if ranked_incidents:
        primary = ranked_incidents[0]
    else:
        primary = {
            "incident_type": "Generic service degradation",
            "domain": "general",
            "severity": "medium",
            "match_count": 0,
            "signal": "The signals do not map cleanly to one known incident pattern yet.",
            "summary": "This still looks like a real operational issue, but it needs more targeted telemetry or service-specific runbooks.",
            "causes": [
                "The incident context is too small or too noisy for confident classification",
                "The failure may be application-specific rather than a common platform problem",
                "Recent changes may not be represented in the pasted logs yet",
            ],
            "actions": [
                "Pull service-specific logs, metrics, and deployment events into the next triage pass.",
                "Compare the current revision with the last healthy deployment window.",
                "Add ownership and environment metadata to the alert payload.",
            ],
            "automation": [
                "Standardize alert payloads so service, environment, and rollout ID are always present.",
            ],
        }

    severity = _derive_severity(primary["severity"], combined_text, manifest_findings)
    confidence = min(
        95,
        44 + (primary["match_count"] * 14) + (min(len(manifest_findings), 4) * 5),
    )

    if not ranked_incidents:
        confidence = min(confidence, 61)

    probable_causes = list(primary["causes"])
    if any("secret exposed as plain text" in finding["title"].lower() for finding in manifest_findings):
        probable_causes.append("Secret management is mixed into the deployment manifest instead of a safer secret reference flow.")
    if any("floating image tag" in finding["title"].lower() for finding in manifest_findings):
        probable_causes.append("A floating image tag can make the deployed artifact drift from the intended release.")

    recommended_actions = list(primary["actions"])
    if manifest_findings:
        recommended_actions.append("Fix the highlighted manifest hardening gaps before the next production rollout.")

    automation_opportunities = list(primary["automation"])
    if manifest_findings:
        automation_opportunities.append("Add policy-as-code checks for manifest guardrails inside CI.")

    matched_signals = [incident["incident_type"] for incident in ranked_incidents]
    timeline = _build_timeline(alert_text, primary, change_text, manifest_findings)

    impact_statement = {
        "low": "Limited operational risk is visible from the current input.",
        "medium": "This incident can slow delivery or degrade reliability if it repeats.",
        "high": "This incident is likely blocking a release or disrupting a service path.",
        "critical": "This incident looks production-impacting and should be treated as an urgent recovery path.",
    }[severity]

    postmortem = {
        "What happened": primary["summary"],
        "Customer impact": impact_statement,
        "Probable root cause": probable_causes[0],
        "Immediate next step": recommended_actions[0],
        "Prevention": automation_opportunities[0],
    }

    return {
        "incident_type": primary["incident_type"],
        "domain": primary["domain"],
        "severity": severity,
        "confidence": confidence,
        "summary": primary["summary"],
        "impact_statement": impact_statement,
        "matched_signals": matched_signals,
        "probable_causes": _unique(probable_causes),
        "recommended_actions": _unique(recommended_actions),
        "automation_opportunities": _unique(automation_opportunities),
        "manifest_findings": manifest_findings,
        "timeline": timeline,
        "postmortem": postmortem,
    }
