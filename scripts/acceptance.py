#!/usr/bin/env python3
"""Verify admission through two real server processes sharing PostgreSQL.

Uses only generated attendees and credentials. PostgreSQL must already be
running. Each invocation creates its own event and never clears shared tables.
"""

from __future__ import annotations

import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid


def identifier() -> str:
    return str(uuid.uuid4())


def token() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


class Server:
    def __init__(self, binary: Path, database_url: str, state: Path) -> None:
        self.binary = binary
        self.database_url = database_url
        state.mkdir(mode=0o700)
        self.state = state
        self.owner = token()
        credential = state / "owner.token"
        credential.write_text(self.owner)
        credential.chmod(0o600)
        self.process: subprocess.Popen | None = None
        self.log = (state / "server.log").open("w+")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            self.port = listener.getsockname()[1]
        self.origin = f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        environment = {
            **os.environ, "DATABASE_URL": self.database_url,
            "GATEPASS_STATE_DIR": str(self.state),
            "GATEPASS_OWNER_TOKEN_FILE": str(self.state / "owner.token"),
        }
        self.process = subprocess.Popen(
            [str(self.binary), "serve", "--hostname", "127.0.0.1", "--port", str(self.port)],
            env=environment, stdout=self.log, stderr=self.log,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError("GatePass server stopped before becoming ready")
            try:
                self.call("GET", "/health", None)
                return
            except (URLError, ConnectionError, TimeoutError):
                time.sleep(0.1)
        raise TimeoutError("GatePass server did not become ready")

    def stop(self, crash: bool = False) -> None:
        if self.process is None or self.process.poll() is not None:
            return
        self.process.kill() if crash else self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()

    def call(self, method: str, path: str, credential: str | None,
             body: dict | None = None, expected=(200,)):
        headers = {"Content-Type": "application/json"}
        if credential is not None:
            headers["Authorization"] = "Bearer " + credential
        request = Request(self.origin + path,
                          data=json.dumps(body).encode() if body is not None else None,
                          headers=headers, method=method)
        try:
            with urlopen(request, timeout=20) as response:
                status, data, result_headers = response.status, response.read(), response.headers
        except HTTPError as error:
            status, data, result_headers = error.code, error.read(), error.headers
        check(status in expected, f"{method} {path} returned {status}, expected {expected}")
        return (json.loads(data) if data else None), result_headers


def verify(primary: Server, secondary: Server) -> None:
    primary.start()
    secondary.start()
    event = identifier()
    admin = f"/v1/admin/events/{event}"
    public = f"/v1/events/{event}"
    primary.call("POST", "/v1/admin/events", None,
                 {"id": event, "title": "Synthetic acceptance event", "timezone": "UTC"}, expected=(401,))
    primary.call("POST", "/v1/admin/events", primary.owner,
                 {"id": event, "title": "Synthetic acceptance event", "timezone": "UTC"})

    credentials = []
    devices = []
    expiry = (datetime.now(timezone.utc) + timedelta(days=1)).replace(microsecond=0).isoformat()
    for label in ["Entrance A", "Entrance B"]:
        secret, device = token(), identifier()
        primary.call("POST", admin + "/devices", primary.owner,
                     {"id": device, "label": label, "credential_hash": digest(secret), "expires_at": expiry})
        credentials.append(secret)
        devices.append(device)

    secrets_by_ticket = [token() for _ in range(5)]
    tickets = [
        {"id": identifier(), "external_id": f"{index:05d}",
         "display_name": f"Synthetic guest {index}", "token_hash": digest(secret)}
        for index, secret in enumerate(secrets_by_ticket)
    ]
    batch = identifier()
    primary.call("POST", admin + "/imports", primary.owner, {"batch_id": batch, "tickets": tickets})
    _, headers = primary.call("POST", admin + "/imports", primary.owner,
                              {"batch_id": batch, "tickets": tickets})
    check(headers.get("GatePass-Replayed") == "true", "Import retry was not recognized")

    def scan(index: int, ticket_index: int = 0, operation: str | None = None):
        server = primary if index % 2 == 0 else secondary
        credential = credentials[index % 2]
        return server.call("POST", public + "/scans", credential,
                           {"operation_id": operation or identifier(), "scanned_event_id": event,
                            "ticket_secret": secrets_by_ticket[ticket_index]})[0]

    with ThreadPoolExecutor(max_workers=16) as executor:
        decisions = list(executor.map(scan, range(100)))
    check(sum(item["decision"] == "accepted" for item in decisions) == 1,
          "Concurrent scans did not produce exactly one admission")
    check(sum(item["decision"] == "already_admitted" for item in decisions) == 99,
          "Duplicate scans did not resolve consistently")
    stats, _ = primary.call("GET", public + "/stats", credentials[0])
    check(stats["admitted"] == 1, "Admission count includes duplicate operations")
    print("PASS 100 concurrent scans across two server processes preserve one admission")

    operation = identifier()
    request = {"operation_id": operation, "scanned_event_id": event,
               "ticket_secret": secrets_by_ticket[1]}

    def repeat(_: int):
        return primary.call("POST", public + "/scans", credentials[0], request)[0]

    with ThreadPoolExecutor(max_workers=16) as executor:
        responses = list(executor.map(repeat, range(100)))
    check(all(result == responses[0] for result in responses), "Operation replay changed the stored response")
    check(responses[0]["decision"] == "accepted", "Repeated operation did not retain original acceptance")
    primary.call("POST", public + "/scans", credentials[0],
                 {**request, "ticket_secret": secrets_by_ticket[2]}, expected=(409,))
    print("PASS 100 copies of one operation replay exactly and reject changed payload")

    # Treat a committed response as unacknowledged, then resolve after a crash.
    primary.stop(crash=True)
    primary.start()
    recovered, headers = primary.call("GET", public + f"/devices/me/scans/{operation}", credentials[0])
    check(recovered == responses[0], "Server restart lost the committed scan decision")
    check(headers.get("GatePass-Replayed") == "true", "Recovery response lacks historical-result marker")
    print("PASS server crash preserves the result needed for ambiguous-response recovery")

    wrong, _ = primary.call("POST", public + "/scans", credentials[0],
                            {"operation_id": identifier(), "scanned_event_id": identifier(),
                             "ticket_secret": secrets_by_ticket[2]})
    check(wrong["decision"] == "wrong_event" and "display_name" not in wrong,
          "Foreign-event scan leaked roster data or admitted a guest")
    primary.call("POST", admin + f"/tickets/{tickets[3]['id']}/revoke", primary.owner, {})
    check(scan(0, ticket_index=3)["decision"] == "revoked", "Revoked ticket was admitted")
    primary.call("POST", admin + f"/devices/{devices[1]}/revoke", primary.owner, {})
    secondary.call("POST", public + "/scans", credentials[1],
                   {"operation_id": identifier(), "scanned_event_id": event,
                    "ticket_secret": secrets_by_ticket[4]}, expected=(401, 403))
    primary.call("POST", admin + "/close", primary.owner, {})
    check(scan(0, ticket_index=4)["decision"] == "event_closed", "Closed event admitted a new guest")
    attendance, _ = primary.call("GET", admin + "/attendance", primary.owner)
    check(sum(item["status"] == "admitted" for item in attendance["attendees"]) == 2,
          "Attendance export disagrees with authoritative admissions")
    print("PASS event isolation, ticket/device revocation, closure and attendance export")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path(".build/debug/GatePassServer"))
    parser.add_argument("--database-url", default=os.environ.get(
        "DATABASE_URL", "postgres://gatepass@127.0.0.1:5433/gatepass?sslmode=disable"))
    args = parser.parse_args()
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error("Build GatePassServer before running HTTP acceptance")
    with tempfile.TemporaryDirectory(prefix="gatepass-acceptance-") as directory:
        root = Path(directory)
        primary = Server(binary, args.database_url, root / "a")
        secondary = Server(binary, args.database_url, root / "b")
        try:
            verify(primary, secondary)
            print("All PostgreSQL and HTTP acceptance checks passed with synthetic attendees.")
        finally:
            primary.stop()
            secondary.stop()
            primary.log.close()
            secondary.log.close()


if __name__ == "__main__":
    main()
