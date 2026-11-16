# Global Glory

Full-stack manual guild operations dashboard built with FastAPI, SQLAlchemy and a responsive frontend.

## Features
- Email/password registration and signed HTTP-only sessions
- User dashboard, guild ID/name/level profiles
- Manual squad session records (1 demo credit per session)
- Manual glory submissions with admin review
- Demo credit requests at $1 per credit, order ID + transaction reference
- Admin analytics, user activation, credit adjustments and review queues
- SQLite locally; PostgreSQL via DATABASE_URL
- Docker and Render deployment files

## Safety and demo limitations
This is a manual-record demo. It does not automate gameplay, connect to game servers, read game packets or verify in-game glory. All glory records require human admin review. Demo orders do not collect money or verify a payment-provider transaction; approval only grants demo credits.

## Local setup
Python 3.11+:
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Set ADMIN_EMAIL, ADMIN_PASSWORD and a long random SECRET_KEY
uvicorn app.main:app --reload
```
Open http://127.0.0.1:8000. The first admin account is seeded at startup if ADMIN_EMAIL and ADMIN_PASSWORD are configured.

## Render deployment
Create a Docker Web Service from this repository. Add a PostgreSQL database and configure DATABASE_URL with its internal connection string. Set ADMIN_EMAIL and a strong ADMIN_PASSWORD as private environment variables. Keep COOKIE_SECURE=true on HTTPS. Never commit credentials. Use the included render.yaml as a Blueprint starting point.

API documentation: /docs · Health check: /health
