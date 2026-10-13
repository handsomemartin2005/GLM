"""Minimal OpenAI-compatible client; never include credentials in artifacts."""
import json
import os
import time
import urllib.error
import urllib.request

def credential(name):
    value = os.environ.get(name, "").strip()
    if os.name == "nt":
        import winreg
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as reg:
                value = str(winreg.QueryValueEx(reg, name)[0]).strip()
        except FileNotFoundError:
            pass
    if len(value) < 16 or any(c.isspace() for c in value):
        raise ValueError("Credential unavailable for " + name)
    return value

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None

def complete(endpoint, key, body, secrets):
    start = time.monotonic()
    request = urllib.request.Request(endpoint, data=json.dumps(body).encode(), headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    result = {}
    try:
        try:
            response = urllib.request.build_opener(NoRedirect).open(request, timeout=60)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            result["http_status"] = response.code
            text = response.read(1000000).decode("utf-8", "replace")
            for secret in secrets:
                text = text.replace(secret, "[REDACTED_CREDENTIAL]")
            try:
                result["response"] = json.loads(text)
            except ValueError:
                result["response_text"] = text
    except Exception as exc:
        result["error"] = type(exc).__name__
    result["elapsed_seconds"] = round(time.monotonic() - start, 3)
    return result

def parse(response):
    data = response.get("response")
    if response.get("http_status") != 200 or not isinstance(data, dict):
        return None, "api_error", None
    choices = data.get("choices") or []
    if not choices:
        return None, "api_error", None
    choice = choices[0]
    message = choice.get("message") or {}
    if choice.get("finish_reason") == "length":
        return None, "truncated", message
    calls = message.get("tool_calls") or []
    try:
        if calls:
            if len(calls) > 8 or any(c["function"]["name"] != "execute" for c in calls):
                return None, "parse_error", message
            actions = [json.loads(c["function"]["arguments"]) for c in calls]
        else:
            content = message.get("content") or ""
            if not isinstance(content, str):
                return None, "parse_error", message
            if content.strip().startswith("```"):
                content = content.strip().split("\n", 1)[1].rsplit("```", 1)[0]
            if not content.strip():
                return None, "parse_error", message
            if not content.strip().startswith("{"):
                return [], None, message
            actions = [json.loads(content)]
        for i, action in enumerate(actions):
            if not isinstance(action, dict) or not isinstance(action.get("action"), str) or not isinstance(action.get("arguments", {}), dict):
                return None, "parse_error", message
            if action["action"] == "finish" and i != len(actions) - 1:
                return None, "parse_error", message
        return actions, None, message
    except (KeyError, ValueError, TypeError):
        return None, "parse_error", message

