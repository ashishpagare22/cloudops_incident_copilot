# CloudOps Incident Copilot

CloudOps Incident Copilot is a compact resume project that blends cloud engineering, DevOps workflows, and AI-style incident triage.

It accepts:

- alert or pager context
- Kubernetes logs or CI/CD logs
- optional deployment manifests
- recent change notes

It produces:

- incident classification with confidence
- probable root-cause hints
- recommended remediation steps
- Kubernetes manifest guardrail findings
- automation ideas for stronger DevOps workflows
- a postmortem-ready summary

## Why this is a strong resume project

- It demonstrates practical cloud and DevOps knowledge instead of only generic AI chat behavior.
- It shows you can turn noisy operational signals into structured decisions.
- It includes real engineering packaging: tests, Docker, and GitHub Actions CI.
- It is small enough to finish and explain clearly in interviews.

## Tech stack

- Python
- Streamlit
- PyYAML
- Pytest
- Docker
- GitHub Actions

## Run locally

```bash
cd cloudops_incident_copilot
pip install -r requirements.txt
streamlit run app.py
```

## Test locally

```bash
cd cloudops_incident_copilot
python -m pytest
```

## Docker

```bash
cd cloudops_incident_copilot
docker build -t cloudops-incident-copilot .
docker run -p 8501:8501 cloudops-incident-copilot
```

## Sample scenarios

- Kubernetes rollout incident with crash loops, probe failures, and weak manifest guardrails
- GitHub Actions deployment failure caused by registry or IAM credential drift

## Good resume bullets

- Built a CloudOps incident triage dashboard that classifies Kubernetes and CI/CD failures and generates remediation guidance from logs and deployment context.
- Added manifest guardrail analysis for image tagging, resource requests and limits, health probes, and secret handling.
- Packaged the project with Docker and automated test validation with GitHub Actions.
