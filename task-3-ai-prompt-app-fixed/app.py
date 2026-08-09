import csv
import io
import os
import sqlite3
import urllib.error
import urllib.request
import json
from datetime import datetime, timezone

from flask import Flask, Response, render_template, request
from dotenv import load_dotenv

load_dotenv()

from models import init_db, log_prompt, fetch_history, fetch_counters

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_REQUEST_BYTES", "20000"))

MAX_PROMPT_LENGTH = int(os.getenv("MAX_PROMPT_LENGTH", "1000"))
AI_TIMEOUT_SECONDS = float(os.getenv("AI_TIMEOUT_SECONDS", "15"))
AI_API_URL = os.getenv("AI_API_URL", "https://api.openai.com/v1/chat/completions")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini")
AI_API_KEY = os.getenv("AI_API_KEY", "").strip()

TEMPLATES = {
    "General Assistant": "You are a helpful assistant.",
    "Code Review & Debugging": "You are a careful software engineer. Review code and explain bugs and improvements.",
    "Text Summarization": "Summarize the user's content clearly and concisely.",
    "DevOps & Infrastructure": "You are a DevOps and infrastructure assistant. Prefer practical, safe operational guidance.",
}

init_db()


def mock_response(prompt, template):
    # Deterministic response for local testing when no API key is configured.
    return (
        f"[MOCK MODE] Template: {template}. "
        f"Prompt accepted successfully ({len(prompt)} characters). "
        "Configure AI_API_KEY to enable the real provider mode."
    )


def call_real_provider(prompt, template):
    """Call an OpenAI-compatible chat-completions endpoint using environment config."""
    if not AI_API_KEY:
        raise RuntimeError("AI_API_KEY is not configured.")

    payload = {
        "model": AI_MODEL,
        "messages": [
            {"role": "system", "content": TEMPLATES.get(template, TEMPLATES["General Assistant"])},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        AI_API_URL,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {AI_API_KEY}",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=AI_TIMEOUT_SECONDS) as response:
            raw = response.read().decode("utf-8")
            body = json.loads(raw)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"AI provider returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Unable to reach AI provider: {exc.reason}") from exc
    except TimeoutError as exc:
        raise RuntimeError("AI provider request timed out.") from exc
    except json.JSONDecodeError as exc:
        raise RuntimeError("AI provider returned invalid JSON.") from exc

    try:
        content = body["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError("AI provider response did not contain a usable message.") from exc

    return str(content).strip()


def get_ai_response(prompt, template):
    if not AI_API_KEY:
        return mock_response(prompt, template), "Mock"
    return call_real_provider(prompt, template), "Real"


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        prompt = request.form.get("prompt", "").strip()
        template = request.form.get("template", "General Assistant")

        if template not in TEMPLATES:
            template = "General Assistant"

        if not prompt:
            return render_template("index.html", error="Prompt cannot be empty.", templates=TEMPLATES, selected_template=template)

        if len(prompt) > MAX_PROMPT_LENGTH:
            return render_template(
                "index.html",
                error=f"Prompt is too long. Maximum length is {MAX_PROMPT_LENGTH} characters.",
                templates=TEMPLATES,
                selected_template=template,
            )

        try:
            response, mode = get_ai_response(prompt, template)
            log_prompt(prompt, template, mode, response, "Success")
            counters = fetch_counters()
            return render_template(
                "index.html",
                response=response,
                mode=mode,
                templates=TEMPLATES,
                selected_template=template,
                counters=counters,
            )
        except Exception as exc:
            error_message = str(exc)
            # Do not expose secrets or internal traceback details to the user.
            log_prompt(prompt, template, "Real" if AI_API_KEY else "Mock", error_message, "Error")
            return render_template(
                "index.html",
                error=f"AI request failed: {error_message}",
                templates=TEMPLATES,
                selected_template=template,
            ), 502

    return render_template("index.html", templates=TEMPLATES, selected_template="General Assistant", counters=fetch_counters())


@app.route("/history")
def history():
    search = request.args.get("search", "").strip()
    data = fetch_history(search)
    return render_template("history.html", history=data, search=search)


@app.route("/export")
def export_csv():
    rows = fetch_history("")
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Prompt", "Template", "Mode", "Response", "Status"])
    writer.writerows(rows)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=prompt_history.csv"},
    )


@app.errorhandler(413)
def request_too_large(_error):
    return render_template("index.html", error="Request is too large.", templates=TEMPLATES, selected_template="General Assistant"), 413


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=False)
