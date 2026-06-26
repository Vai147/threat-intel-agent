# Threat Intelligence Enrichment Agent

A Claude-powered agent that investigates Indicators of Compromise (IOCs) by
querying threat-intelligence sources, cross-referencing findings, mapping them
to MITRE ATT&CK, and producing a structured report.

Based on the Anthropic cookbook
[Tool Use: Threat Intel Enrichment Agent](https://platform.claude.com/cookbook/tool-use-threat-intel-enrichment-agent),
restructured into a modular, testable package with a swappable data-source layer.

## How it works

```
IOC ──▶ agent loop ──▶ Claude picks a tool
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
        IntelBackend            (loops, cross-references,
     (mock or real APIs)         maps to MITRE ATT&CK)
              │                       │
              └──────────▶ free-text analysis ──▶ structured JSON report
```

Claude decides which of four tools to call, the backend returns data, results
feed back, and the loop runs until Claude finishes (`end_turn`) or hits the
turn budget. The free-text assessment is then converted to a JSON report that
matches a fixed schema.

## Layout

| File | Responsibility |
|------|----------------|
| `config.py` | API key, model id, Anthropic client |
| `tools.py` | The four tool schemas shown to Claude |
| `backends.py` | `IntelBackend` interface + `MockIntelBackend` fixtures |
| `agent.py` | The agent loop and tool dispatch |
| `report.py` | Report schema + free-text → JSON conversion |
| `cli.py` | Command-line entry point |

The four tools: `lookup_ip_reputation`, `lookup_file_hash`, `lookup_domain`,
`get_mitre_techniques`.

## Setup

```bash
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env   # add your ANTHROPIC_API_KEY
```

## Usage

```bash
# Free-text assessment (mock data, no extra keys)
python -m threat_intel.cli investigate 203.0.113.42 --type ip_address

# With the structured JSON report
python -m threat_intel.cli investigate d131dd02c5e6eec4693d9a0698aff95c --type file_hash --json

# Write the report to a file
python -m threat_intel.cli investigate secure-bankofamerica-login.com --type domain --out report.json
```

`--type` is one of: `ip_address`, `file_hash`, `domain`, `url`, `email`.

Three indicators have rich, correlated fixture data so the agent demonstrates
multi-source pivoting (hash → contacted IPs → MITRE):

- IP `203.0.113.42` (Emotet C2)
- MD5 `d131dd02c5e6eec4693d9a0698aff95c` (Emotet DLL)
- Domain `secure-bankofamerica-login.com` (phishing)

Any other indicator returns deterministic generated data.

## Real data (free)

The mock backend is enough to demo the agent, but you can enrich against **real,
live threat intelligence** using three free APIs. No paid SIEM required.

Get free keys and put them in `.env`:

| Service | Used for | Free key |
|---------|----------|----------|
| VirusTotal | hash / domain / IP reputation | https://www.virustotal.com/gui/my-apikey |
| AbuseIPDB | IP abuse score | https://www.abuseipdb.com/account/api |
| abuse.ch ThreatFox | the live IOC feed | https://auth.abuse.ch/ |

Live enrichment of a single IOC:

```bash
python -m threat_intel.cli investigate 1.1.1.1 --type ip_address --backend live --json
```

Pull **real recent IOCs** from ThreatFox and investigate each (this is the
"generate real IOCs" part — abuse.ch shares indicators seen in the wild):

```bash
# print results
python -m threat_intel.cli feed --source threatfox --days 1 --limit 3 --backend live

# or write one JSON report per IOC into a folder
python -m threat_intel.cli feed --days 1 --limit 5 --backend live --out reports/
```


Run both processes:

```bash
# 1. backend (from repo root, venv active)
PYTHONPATH=src .venv/bin/python -m uvicorn threat_intel.api:app --port 8000

# 2. frontend (in another terminal)
cd frontend
npm install
npm run dev          # opens http://localhost:5173
```

The backend reads the same `.env` (Anthropic key required; the live backend and
feed need the free threat-intel keys). The mock backend works with only the
Anthropic key, so the UI demos with no extra setup.

Backend endpoints:

| Endpoint | Purpose |
|----------|---------|
| `GET /api/health` | liveness |
| `GET /api/feed?days=&limit=` | recent real IOCs (ThreatFox) |
| `GET /api/investigate/stream?ioc=&type=&backend=` | SSE: live tool calls + report |


### Test the production image locally

```bash
docker build -t threat-intel .
docker run -p 8000:8000 --env-file .env threat-intel
# open http://localhost:8000
```

## Tests

```bash
.venv/bin/python -m pytest -q          # backend, offline
cd frontend && npm run build           # frontend typecheck + build
```
