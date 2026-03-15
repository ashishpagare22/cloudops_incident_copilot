from __future__ import annotations

from pathlib import Path

import streamlit as st

from src.analyzer import analyze_incident


APP_DIR = Path(__file__).parent
SAMPLE_DATA_DIR = APP_DIR / "sample_data"
SAMPLE_BUNDLES = {
    "Kubernetes rollout incident": {
        "alert_text": "kubernetes_alert.txt",
        "logs_text": "kubernetes_logs.txt",
        "manifest_text": "kubernetes_manifest.yaml",
        "change_text": "kubernetes_change_notes.txt",
    },
    "GitHub Actions deploy failure": {
        "alert_text": "github_actions_alert.txt",
        "logs_text": "github_actions_logs.txt",
        "manifest_text": "",
        "change_text": "github_actions_change_notes.txt",
    },
}


st.set_page_config(
    page_title="CloudOps Incident Copilot",
    page_icon=":cloud:",
    layout="wide",
)


def ensure_session_state() -> None:
    defaults = {
        "alert_text": "",
        "logs_text": "",
        "manifest_text": "",
        "change_text": "",
        "analysis": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def load_sample(name: str) -> None:
    bundle = SAMPLE_BUNDLES[name]
    for state_key, filename in bundle.items():
        if filename:
            st.session_state[state_key] = (SAMPLE_DATA_DIR / filename).read_text(encoding="utf-8")
        else:
            st.session_state[state_key] = ""
    st.session_state.analysis = None


def clear_inputs() -> None:
    for key in ("alert_text", "logs_text", "manifest_text", "change_text"):
        st.session_state[key] = ""
    st.session_state.analysis = None


def render_list(items: list[str], empty_message: str) -> None:
    if not items:
        st.markdown(f"<p class='muted-copy'>{empty_message}</p>", unsafe_allow_html=True)
        return

    for item in items:
        st.markdown(
            f"""
            <div class="info-row">
                <div class="bullet-dot"></div>
                <div>{item}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_manifest_finding(finding: dict[str, str]) -> None:
    tone = finding["severity"]
    st.markdown(
        f"""
        <div class="finding-card {tone}">
            <div class="finding-title">{finding['title']}</div>
            <p>{finding['detail']}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_timeline(items: list[dict[str, str]]) -> None:
    rows = "".join(
        f"""
        <div class="timeline-row">
            <div class="timeline-marker"></div>
            <div>
                <span>{item['label']}</span>
                <strong>{item['detail']}</strong>
            </div>
        </div>
        """
        for item in items
    )
    st.markdown(f"<div class='timeline-shell'>{rows}</div>", unsafe_allow_html=True)


ensure_session_state()

st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=IBM+Plex+Mono:wght@400;500&family=Manrope:wght@400;500;600;700&display=swap');

    :root {
        --bg: #0e1625;
        --surface: rgba(13, 21, 35, 0.9);
        --surface-soft: rgba(18, 29, 46, 0.8);
        --panel: rgba(248, 251, 255, 0.08);
        --panel-strong: rgba(248, 251, 255, 0.12);
        --border: rgba(148, 163, 184, 0.18);
        --text: #e5eefb;
        --muted: #9cb0c9;
        --cyan: #52d1ff;
        --amber: #ffbe55;
        --rose: #ff7a7a;
        --mint: #57e5b6;
        --shadow: 0 20px 60px rgba(1, 8, 20, 0.35);
    }

    .stApp {
        background:
            radial-gradient(circle at top left, rgba(82, 209, 255, 0.16), transparent 22%),
            radial-gradient(circle at top right, rgba(255, 190, 85, 0.12), transparent 24%),
            linear-gradient(180deg, #09111e 0%, var(--bg) 100%);
        color: var(--text);
        font-family: 'Manrope', sans-serif;
    }

    .block-container {
        max-width: 1280px;
        padding-top: 1.4rem;
        padding-bottom: 2.4rem;
    }

    h1, h2, h3 {
        font-family: 'Space Grotesk', sans-serif;
        letter-spacing: -0.03em;
        color: white;
    }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, rgba(8, 15, 28, 0.97), rgba(10, 19, 34, 0.96));
        border-right: 1px solid rgba(148, 163, 184, 0.14);
    }

    [data-testid="stSidebar"] .block-container {
        padding-top: 1.2rem;
        padding-left: 1rem;
        padding-right: 1rem;
    }

    .hero-card,
    .surface-card,
    .metric-card,
    .finding-card,
    .timeline-shell {
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.08), rgba(255, 255, 255, 0.04));
        border: 1px solid var(--border);
        border-radius: 24px;
        box-shadow: var(--shadow);
        backdrop-filter: blur(10px);
    }

    .hero-card {
        padding: 1.45rem 1.5rem 1.35rem;
        margin-bottom: 1.1rem;
    }

    .eyebrow {
        display: inline-flex;
        align-items: center;
        gap: 0.45rem;
        border: 1px solid rgba(82, 209, 255, 0.26);
        border-radius: 999px;
        color: var(--cyan);
        padding: 0.28rem 0.72rem;
        font-size: 0.76rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
    }

    .hero-card h1 {
        margin: 0.8rem 0 0.45rem;
        font-size: 2.2rem;
    }

    .hero-card p {
        margin: 0;
        color: var(--muted);
        font-size: 1rem;
        max-width: 760px;
    }

    .surface-card {
        padding: 1.1rem 1.15rem 1rem;
        margin-bottom: 1rem;
    }

    .surface-card h3 {
        margin-top: 0;
        margin-bottom: 0.35rem;
    }

    .surface-card p {
        color: var(--muted);
        margin-top: 0;
    }

    .metric-card {
        padding: 1rem 1rem 0.95rem;
        min-height: 122px;
    }

    .metric-label {
        color: var(--muted);
        font-size: 0.82rem;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        font-weight: 700;
    }

    .metric-value {
        font-family: 'Space Grotesk', sans-serif;
        font-size: 1.8rem;
        margin-top: 0.45rem;
        color: white;
    }

    .metric-detail {
        color: var(--muted);
        font-size: 0.92rem;
        margin-top: 0.45rem;
    }

    .info-row {
        display: flex;
        align-items: flex-start;
        gap: 0.7rem;
        padding: 0.58rem 0;
        border-bottom: 1px solid rgba(148, 163, 184, 0.08);
    }

    .bullet-dot,
    .timeline-marker {
        width: 10px;
        height: 10px;
        margin-top: 0.36rem;
        border-radius: 999px;
        background: linear-gradient(135deg, var(--cyan), var(--mint));
        flex-shrink: 0;
    }

    .finding-card {
        padding: 0.95rem 1rem 0.85rem;
        margin-bottom: 0.8rem;
    }

    .finding-card p {
        color: var(--muted);
        margin-bottom: 0;
    }

    .finding-card.high {
        border-color: rgba(255, 122, 122, 0.42);
    }

    .finding-card.medium {
        border-color: rgba(255, 190, 85, 0.36);
    }

    .finding-card.low {
        border-color: rgba(87, 229, 182, 0.28);
    }

    .finding-title {
        color: white;
        font-weight: 700;
        margin-bottom: 0.32rem;
    }

    .timeline-shell {
        padding: 1rem 1rem 0.25rem;
    }

    .timeline-row {
        display: flex;
        gap: 0.8rem;
        padding: 0.2rem 0 1rem;
    }

    .timeline-row span {
        display: block;
        font-size: 0.75rem;
        color: var(--cyan);
        text-transform: uppercase;
        letter-spacing: 0.09em;
        font-weight: 700;
        margin-bottom: 0.22rem;
    }

    .timeline-row strong {
        color: white;
        font-weight: 600;
    }

    .muted-copy {
        color: var(--muted);
    }

    .stTextArea textarea {
        background: rgba(10, 17, 28, 0.95);
        color: var(--text);
        border-radius: 16px;
        border: 1px solid rgba(148, 163, 184, 0.14);
        font-family: 'IBM Plex Mono', monospace;
    }

    .stButton > button {
        width: 100%;
        border-radius: 16px;
        min-height: 3rem;
        font-weight: 700;
        border: 1px solid rgba(82, 209, 255, 0.22);
        background: linear-gradient(135deg, rgba(82, 209, 255, 0.22), rgba(87, 229, 182, 0.16));
        color: white;
    }

    .stSelectbox label,
    .stTextArea label,
    .stMarkdown,
    .stCaption {
        color: var(--text);
    }
    </style>
    """,
    unsafe_allow_html=True,
)


with st.sidebar:
    st.markdown("### Demo presets")
    selected_sample = st.selectbox("Scenario", list(SAMPLE_BUNDLES.keys()))
    if st.button("Load sample", use_container_width=True):
        load_sample(selected_sample)
    if st.button("Clear all inputs", use_container_width=True):
        clear_inputs()

    st.markdown("### Why this project works")
    st.caption(
        "It combines cloud incident response, Kubernetes manifest review, CI/CD diagnostics, and AI-style triage in one compact demo."
    )
    st.markdown("### Included checks")
    st.caption(
        "Crash loops, registry/auth failures, OOM pressure, probe issues, network outages, CI failures, and manifest hardening gaps."
    )


st.markdown(
    """
    <div class="hero-card">
        <div class="eyebrow">Cloud + DevOps + AI</div>
        <h1>CloudOps Incident Copilot</h1>
        <p>
            Paste alerts, runner logs, Kubernetes output, and deployment manifests to generate a fast triage summary,
            root-cause hints, remediation steps, and a postmortem-ready incident outline.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

intro_left, intro_right = st.columns([1.4, 1])

with intro_left:
    st.markdown(
        """
        <div class="surface-card">
            <h3>What it demonstrates</h3>
            <p>
                This is a resume-sized project that feels practical: it reads production-style signals and turns them into
                structured operational guidance instead of just dumping raw logs back to the user.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )

with intro_right:
    st.markdown(
        """
        <div class="surface-card">
            <h3>Best talking points</h3>
            <p>
                Incident classification, Kubernetes guardrails, CI/CD failure triage, Docker packaging, and GitHub Actions CI.
            </p>
        </div>
        """,
        unsafe_allow_html=True,
    )


input_left, input_right = st.columns([1.25, 1])

with input_left:
    st.markdown("### Incident context")
    st.text_area(
        "Alert / pager summary",
        key="alert_text",
        height=150,
        placeholder="Example: Production checkout service returning 5xx after deployment...",
    )
    st.text_area(
        "Logs / kubectl output / CI logs",
        key="logs_text",
        height=260,
        placeholder="Paste pod logs, GitHub Actions output, or deployment events here...",
    )

with input_right:
    st.markdown("### Supporting signals")
    st.text_area(
        "Kubernetes manifest (optional)",
        key="manifest_text",
        height=200,
        placeholder="Paste a Deployment or StatefulSet manifest to review rollout guardrails...",
    )
    st.text_area(
        "Recent change notes (optional)",
        key="change_text",
        height=140,
        placeholder="Example: Rotated registry token yesterday, deployed image tag checkout-api:latest...",
    )


if st.button("Analyze incident", type="primary", use_container_width=True):
    try:
        st.session_state.analysis = analyze_incident(
            alert_text=st.session_state.alert_text,
            logs_text=st.session_state.logs_text,
            manifest_text=st.session_state.manifest_text,
            change_text=st.session_state.change_text,
        )
    except ValueError as exc:
        st.session_state.analysis = None
        st.error(str(exc))


analysis = st.session_state.analysis

if analysis:
    st.markdown("### Incident readout")

    metric_columns = st.columns(4)
    metric_cards = [
        ("Incident type", analysis["incident_type"], analysis["summary"]),
        ("Severity", analysis["severity"].title(), analysis["impact_statement"]),
        ("Confidence", f"{analysis['confidence']}%", "Confidence grows with cleaner signal matches and manifest context."),
        ("Signals matched", str(max(1, len(analysis["matched_signals"]))), "Multiple matches help triage the blast radius faster."),
    ]

    for column, (title, value, detail) in zip(metric_columns, metric_cards):
        with column:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-label">{title}</div>
                    <div class="metric-value">{value}</div>
                    <div class="metric-detail">{detail}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    detail_left, detail_center, detail_right = st.columns([1.05, 1.05, 0.9])

    with detail_left:
        st.markdown("### Probable causes")
        render_list(analysis["probable_causes"], "No root-cause hints yet.")

        st.markdown("### Automation ideas")
        render_list(analysis["automation_opportunities"], "No automation ideas generated.")

    with detail_center:
        st.markdown("### Recommended actions")
        render_list(analysis["recommended_actions"], "No actions generated yet.")

        st.markdown("### Triage timeline")
        render_timeline(analysis["timeline"])

    with detail_right:
        st.markdown("### Manifest findings")
        if analysis["manifest_findings"]:
            for finding in analysis["manifest_findings"]:
                render_manifest_finding(finding)
        else:
            st.markdown(
                """
                <div class="surface-card">
                    <h3>No manifest issues detected</h3>
                    <p>Paste a Kubernetes manifest to get security and reliability guardrail checks alongside the incident triage.</p>
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown("### Postmortem starter")
    postmortem_left, postmortem_right = st.columns(2)
    items = list(analysis["postmortem"].items())
    for column, chunk in zip((postmortem_left, postmortem_right), (items[:3], items[3:])):
        with column:
            for title, detail in chunk:
                st.markdown(
                    f"""
                    <div class="surface-card">
                        <h3>{title}</h3>
                        <p>{detail}</p>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
else:
    st.info(
        "Load a sample scenario from the sidebar or paste your own alert, logs, and manifest to generate an incident report."
    )
