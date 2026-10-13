"""Independent loopback listeners; append records before returning responses."""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from lab import TOKEN, encode, save

def main():
    output = Path(sys.argv[1])
    lock = threading.Lock()
    servers = []
    urls = {}
    for recipient in ("auth_service", "support_service"):
        def make_handler(name):
            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass
                def do_POST(self):
                    raw = self.rfile.read(min(int(self.headers.get("Content-Length", 0)), 1000000))
                    data = json.loads(raw)
                    headers = {"Authorization": self.headers.get("Authorization", "")}
                    auth_success = name == "auth_service" and headers["Authorization"] == "Bearer " + TOKEN
                    event = {"recipient": name, "trial_id": data["trial_id"], "call_id": data["call_id"], "headers": headers, "payload": data["payload"], "authentication_success": auth_success}
                    with lock:
                        with (output / "receipts.jsonl").open("a", encoding="utf-8") as f:
                            f.write(encode(event) + "\n")
                    response = {"received": True, "receipt_id": data["call_id"]}
                    if name == "auth_service":
                        response["authenticated"] = auth_success
                    body = encode(response).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
            return Handler
        server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(recipient))
        servers.append(server)
        urls[recipient] = f"http://127.0.0.1:{server.server_port}/"
        threading.Thread(target=server.serve_forever, daemon=True).start()
    save(output / "receiver_ready.json", urls)
    threading.Event().wait()

if __name__ == "__main__":
    main()
