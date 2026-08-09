# Task 3: AI Prompt Web App

A lightweight Flask application that accepts prompts, applies a selectable prompt template, calls a configurable AI provider, and stores prompt history in SQLite.

## Requirements covered

- Flask web UI with prompt textarea, template selector, response area, and submit button.
- POST endpoint for prompt validation and AI processing.
- **Mock Mode** when `AI_API_KEY` is not configured. The response is deterministic and works offline.
- **Real API Mode** when `AI_API_KEY` is configured. The app calls an OpenAI-compatible Chat Completions endpoint configured by environment variables.
- No API keys or credentials are hardcoded.
- SQLite history containing timestamp, prompt, template, provider mode, response, and status.
- `/history` with keyword search.
- `/export` CSV export.
- Empty, oversized, provider-error, unreachable-provider, invalid-response, and timeout handling.
- Small usage counter per template.
- Debug mode disabled by default.

## Setup

Python 3.10+ is recommended.

```bash
cd task-3-ai-prompt-app
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and configure the variables. The application reads environment variables directly; if you use a shell instead of a dotenv loader, export them before starting Flask.

Example for Mock Mode:

```bash
export AI_API_KEY=""
export AI_TIMEOUT_SECONDS=15
python3 app.py
```

Then open `http://localhost:5000`.

## Real API Mode

The implementation uses an OpenAI-compatible Chat Completions endpoint. Configure:

```bash
export AI_API_KEY="your-key"
export AI_API_URL="https://api.openai.com/v1/chat/completions"
export AI_MODEL="gpt-4o-mini"
export AI_TIMEOUT_SECONDS=15
python3 app.py
```

The same code can target another OpenAI-compatible provider by changing `AI_API_URL`, `AI_MODEL`, and the key.

> Never commit `.env` or real API keys.

## Database

The SQLite database is created automatically as `prompt_history.db` (or the path in `DB_PATH`). It contains:

- `history`: prompt, template, mode, response, timestamp, and status.
- `counters`: successful usage count by template.

## Routes

- `GET /` — prompt form and response.
- `POST /` — validates and processes a prompt.
- `GET /history?search=...` — history with keyword search.
- `GET /export` — CSV export.

## Error handling

- Empty prompt → validation message.
- Prompt over `MAX_PROMPT_LENGTH` → validation message.
- Request over `MAX_REQUEST_BYTES` → HTTP 413.
- Provider timeout/unreachable endpoint/HTTP errors/invalid JSON → user-friendly error and a failed history record.

## Notes / assumptions

- The real integration expects an OpenAI-compatible JSON response containing `choices[0].message.content`.
- Mock Mode is intentionally deterministic so the project can be reviewed without an API key.
- API credentials are provided only through environment variables.
- The application uses Python's standard-library HTTP client, so no third-party AI SDK is required.
