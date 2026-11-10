"""The deliberately vulnerable LLM app, plus its secure mode.

INTENTIONALLY VULNERABLE TRAINING TARGET. Run locally only. Do not deploy.

Flow per request: build the challenge's system prompt, (secure mode) screen the
input, call the mock model, (secure mode) sanitize the output, then check whether
the exploit succeeded and hand back a flag if it did. Insecure mode skips the two
guardrails, so the same payload that is blocked in secure mode succeeds here.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend import guardrails, model
from backend.challenges import CHALLENGES, ORDER

FRONTEND = Path(__file__).resolve().parents[1] / "frontend"


def run_challenge(challenge_id: str, message: str, mode: str) -> dict:
    challenge = CHALLENGES[challenge_id]
    secure = mode == "secure"

    if secure:
        refusal = guardrails.screen_input(message)
        if refusal:
            return {"reply": refusal, "solved": False, "mode": mode, "blocked_by": "input-screening"}

    reply = model.generate(challenge.system_prompt, message)
    if secure:
        reply = guardrails.sanitize_output(reply)

    solved = challenge.succeeded(reply)
    result = {"reply": reply, "solved": solved, "mode": mode}
    if solved:
        result["flag"] = challenge.flag
        result["root_cause"] = challenge.root_cause
        result["fix"] = challenge.fix
    return result


def create_app() -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024

    @app.after_request
    def headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        # NOTE: no restrictive Content-Security-Policy is set on purpose. A CSP
        # would block the inline event handler in the LLM05 demo and hide the
        # vulnerability. The fix text explains that a CSP is one of the real
        # mitigations — this lab leaves it off so the insecure demo actually fires.
        return response

    @app.get("/api/challenges")
    def list_challenges():
        return jsonify([
            {"id": c.id, "owasp": c.owasp, "title": c.title,
             "description": c.description, "hint": c.hint}
            for c in (CHALLENGES[i] for i in ORDER)
        ])

    @app.post("/api/chat")
    def chat():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            return jsonify({"error": "expected a JSON object"}), 400
        challenge_id = str(data.get("challenge", ""))
        message = data.get("message", "")
        mode = "secure" if data.get("mode") == "secure" else "insecure"
        if challenge_id not in CHALLENGES:
            return jsonify({"error": f"unknown challenge; choose one of {ORDER}"}), 400
        if not isinstance(message, str) or not message.strip():
            return jsonify({"error": "message must be a non-empty string"}), 400
        return jsonify(run_challenge(challenge_id, message, mode))

    @app.get("/")
    def index():
        return send_from_directory(FRONTEND, "index.html")

    @app.get("/<path:asset>")
    def static_asset(asset: str):
        return send_from_directory(FRONTEND, asset)

    return app


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5001"))
    print(f"LLM Security Lab (intentionally vulnerable) on http://127.0.0.1:{port} — local use only")
    create_app().run(host="127.0.0.1", port=port, debug=False)
