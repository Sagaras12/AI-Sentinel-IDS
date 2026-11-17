# SentinelPulse AI — Local SOC Dashboard

SentinelPulse AI is a Flask-based educational SOC dashboard. It runs locally without Supabase, database credentials, user accounts or a login page. Incident records and preferences are stored in local JSON files under `data/`.

## Setup (Windows PowerShell)

```powershell
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

Edit `.env` and add your Groq key:

```env
AI_PROVIDER=groq
AI_API_KEY=YOUR_GROQ_API_KEY
AI_MODEL=openai/gpt-oss-120b
SECRET_KEY=YOUR_RANDOM_FLASK_SECRET
FLASK_DEBUG=true
```

Get a key from https://console.groq.com/keys. Keep it in `.env`; never put it in frontend JavaScript or commit `.env` to GitHub.

Generate a local Flask secret:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

## Run

```powershell
python app.py
```

Open http://127.0.0.1:5000.

## Features

- Overview dashboard with live local KPIs and Chart.js visualizations.
- Threat Intelligence search, severity/status filtering and record-level mitigation.
- Security Analytics derived from local incident records.
- Attack Simulator for Brute Force, SQL Injection and DDoS (creates sample records only).
- Groq-powered SOC Copilot with current incident context.
- Incident Reports and CSV export.
- Settings for theme, compact mode, refresh interval, in-app notifications and analyst display name.
- Local JSON persistence for incidents and settings.

## API

- `GET /api/health`
- `GET /api/kpis`
- `GET /api/threats?q=&severity=&status=`
- `GET /api/analytics`
- `POST /api/simulate`
- `POST /api/mitigate`
- `POST /api/copilot/chat`
- `GET/POST /api/settings`
- `GET /api/notifications`
- `GET /api/reports`
- `GET /api/export`

## Honest demo limitations

- The app does not ingest live network telemetry, endpoint logs or SIEM events.
- Simulator buttons create sample incident records; no real attack is executed and no network traffic is generated.
- Simulated traffic in the chart is illustrative demo data, not actual network telemetry.
- Mitigation changes only the local incident record status; it does not block an IP or remediate a host.
- Groq Copilot is an LLM assistant whose context is the local incident dataset. Its advice should be validated by an analyst.
- Local JSON data is stored on the machine running Flask. It is not multi-user or suitable for a production SOC deployment.
