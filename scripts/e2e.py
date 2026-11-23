#!/usr/bin/env python3
"""Exercise the real Swift HTTP service and PostgreSQL with synthetic attendees."""
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parent.parent
BIN = ROOT / ".build/debug"
DATABASE = os.environ.get("DATABASE_URL", "postgres://gatepass@127.0.0.1:5433/gatepass?sslmode=disable")


def uid():
    return str(uuid.uuid4())


def api(port, token, method, path, body=None, expected=200):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method,
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        response = urllib.request.urlopen(request, timeout=30)
    except urllib.error.HTTPError as error:
        response = error
    payload = response.read()
    assert response.status == expected, f"{method} {path}: expected {expected}, got {response.status}: {payload[:300]!r}"
    return json.loads(payload), response.headers.get("GatePass-Replayed") == "true"


def main():
    assert (BIN / "GatePassServer").exists(), "Run swift build first"
    checks = []
    with tempfile.TemporaryDirectory(prefix="gatepass-e2e-") as tmp:
        state = Path(tmp)
        owner = secrets.token_urlsafe(32)
        token_file = state / "owner.token"
        token_file.write_text(owner)
        token_file.chmod(0o600)
        servers = []
        logs = []

        def start(port):
            log = open(state / f"server-{port}.log", "ab")
            logs.append(log)
            process = subprocess.Popen([str(BIN / "GatePassServer"), "serve", "--hostname", "127.0.0.1", "--port", str(port)],
                                       cwd=ROOT, stdout=log, stderr=log,
                                       env={**os.environ, "DATABASE_URL": DATABASE, "GATEPASS_OWNER_TOKEN_FILE": str(token_file), "LOG_LEVEL": "error"})
            servers.append(process)
            for _ in range(200):
                if process.poll() is not None:
                    raise AssertionError((state / f"server-{port}.log").read_text()[-3000:])
                try:
                    urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=1).close()
                    return
                except (urllib.error.URLError, TimeoutError):
                    time.sleep(0.1)
            raise AssertionError("Server failed to become ready")

        def cli(action, *args, expect_success=True):
            result = subprocess.run([str(BIN / "GatePassAdmin"), action, "--server", "http://127.0.0.1:8788", "--credential-file", str(token_file), *map(str, args)],
                                    cwd=ROOT, text=True, capture_output=True)
            if expect_success:
                assert result.returncode == 0, f"CLI {action}: {result.stderr[-1000:]}"
                return json.loads(result.stdout)
            assert result.returncode != 0, f"CLI {action} unexpectedly succeeded"
            return result

        try:
            start(8788)
            start(8789)
            event = cli("event-create", "--title", "Synthetic workshop")["id"]
            archive = state / "tickets.gpenc"
            key = state / "archive.key"
            issued_dir = state / "tickets"
            imported = cli("roster-import", "--event", event, "--csv", ROOT / "Fixtures/attendees.csv", "--archive", archive, "--key-file", key, "--output", issued_dir)
            assert imported["count"] == 3
            again = cli("roster-import", "--event", event, "--csv", ROOT / "Fixtures/attendees.csv", "--archive", archive, "--key-file", key, "--output", issued_dir)
            assert again["batch_id"] == imported["batch_id"] and again["replayed"]
            cli("issuance-recover", "--archive", archive, "--key-file", key, "--output", state / "recovered")
            tickets = json.loads((issued_dir / "index.json").read_text())
            assert tickets[0]["external_id"] == "00017"
            assert len(list(issued_dir.glob("*.pdf"))) == 3
            assert archive.read_bytes()[:1] != b"{"
            assert key.stat().st_mode & 0o077 == 0
            checks.append("CSV import, encrypted archive, replay, recovery and QR PDF issuance")

            setups = []
            for index in range(2):
                path = state / f"device-{index}.json"
                cli("device-create", "--event", event, "--label", f"Entrance {index}", "--device-file", path)
                setups.append((json.loads(path.read_text()), path))
            a, a_file = setups[0]
            b, b_file = setups[1]
            codes = [(issued_dir / f"{ticket['id']}.ticket").read_text() for ticket in tickets]
            secrets_ = [code.split(":")[3] for code in codes]
            first = cli("scan", "--device-file", a_file, "--ticket", "@" + str(issued_dir / f"{tickets[0]['id']}.ticket"), "--outbox", state / "first.json")
            assert first["decision"] == "accepted"
            replay = cli("resume", "--device-file", a_file, "--outbox", state / "first.json")
            assert replay["decision"] == "accepted" and replay["review_required"]
            assert json.loads((state / "first.json").read_text()).get("request") is None
            duplicate = cli("scan", "--device-file", b_file, "--ticket", "@" + str(issued_dir / f"{tickets[0]['id']}.ticket"))
            assert duplicate["decision"] == "already_admitted" and duplicate["admitted_by"] == "Entrance 0"
            checks.append("Typed scanner and durable replay clear ticket secrets after resolution")

            def race(i):
                setup = a if i % 2 == 0 else b
                return api(8788 + i % 2, setup["credential"], "POST", f"/v1/events/{event}/scans",
                           {"operation_id": uid(), "scanned_event_id": event, "ticket_secret": secrets_[1]})[0]
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                results = list(pool.map(race, range(100)))
            assert sum(item["decision"] == "accepted" for item in results) == 1
            assert sum(item["decision"] == "already_admitted" for item in results) == 99
            checks.append("100 distinct operations across two server processes admit one ticket once")

            operation = uid()
            body = {"operation_id": operation, "scanned_event_id": event, "ticket_secret": secrets_[2]}
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                results = list(pool.map(lambda i: api(8788 + i % 2, a["credential"], "POST", f"/v1/events/{event}/scans", body), range(100)))
            assert all(value == results[0][0] for value, _ in results)
            assert sum(not replayed for _, replayed in results) == 1
            api(8788, a["credential"], "POST", f"/v1/events/{event}/scans", {**body, "ticket_secret": secrets_[0]}, expected=409)
            assert cli("stats", "--device-file", a_file)["admitted"] == 3
            checks.append("100 same-operation retries replay exactly one decision; changed request returns409")

            extra_secret = secrets.token_urlsafe(32)
            extra_id = uid()
            extra_records = [{"id": extra_id, "external_id": "extra-" + uid(), "display_name": "Synthetic & Guest+One", "token_hash": hashlib.sha256(extra_secret.encode()).hexdigest()}]
            api(8788, owner, "POST", f"/v1/admin/events/{event}/imports", {"batch_id": uid(), "tickets": extra_records})
            matches = cli("lookup", "--device-file", a_file, "--query", "Synthetic & Guest+One")["attendees"]
            assert len(matches) == 1 and matches[0]["id"] == extra_id
            result = subprocess.run(["psql", DATABASE, "-v", "ON_ERROR_STOP=1", "-c", f"UPDATE tickets SET admitted_at=now() WHERE id='{extra_id}'::uuid"], capture_output=True, text=True)
            assert result.returncode != 0 and "ticket_admission_metadata" in result.stderr
            checks.append("PostgreSQL constraint rejects partial admission metadata")

            pending_op = uid()
            pending_request = {"operation_id": pending_op, "scanned_event_id": event, "ticket_secret": extra_secret}
            pending_path = state / "pending.json"
            pending_path.write_text(json.dumps({"operationID": pending_op, "eventID": event, "deviceID": a["deviceID"], "request": pending_request, "acknowledged": False}))
            pending_path.chmod(0o600)
            committed = api(8788, a["credential"], "POST", f"/v1/events/{event}/scans", pending_request)[0]
            for process in servers:
                process.terminate()
            for process in servers:
                process.wait(timeout=20)
            servers.clear()
            start(8788)
            start(8789)
            recovered = cli("resume", "--device-file", a_file, "--outbox", pending_path)
            assert recovered["decision"] == committed["decision"] == "accepted"
            assert recovered["operation_id"] == pending_op and recovered["review_required"]
            assert cli("stats", "--device-file", a_file)["admitted"] == 4
            checks.append("Pending client outbox recovers a committed result after both servers restart")

            api(8788, "invalid", "GET", f"/v1/events/{event}/stats", expected=401)
            wrong = api(8788, a["credential"], "POST", f"/v1/events/{event}/scans", {"operation_id":uid(),"scanned_event_id":uid(),"ticket_secret":extra_secret})[0]
            assert wrong["decision"] == "wrong_event" and "display_name" not in wrong
            cli("revoke-device", "--event", event, "--device-id", b["deviceID"])
            api(8788, b["credential"], "GET", f"/v1/events/{event}/stats", expected=401)
            cli("close", "--event", event)
            closed = api(8788, a["credential"], "POST", f"/v1/events/{event}/scans", {"operation_id":uid(),"scanned_event_id":event,"ticket_secret":extra_secret})[0]
            assert closed["decision"] == "event_closed"
            historical, replayed = api(8789, a["credential"], "POST", f"/v1/events/{event}/scans", pending_request)
            assert historical == committed and replayed
            checks.append("Authorization, device revocation, wrong-event privacy and closure preserve historical replay")

            attendance = state / "attendance.csv"
            cli("attendance-export", "--event", event, "--output", attendance)
            assert '"00017"' in attendance.read_text()
            checks.append("Attendance exports preserve source identifiers")
            print(json.dumps({"passed": len(checks), "checks": checks}, indent=2))
        finally:
            for process in servers:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
            for log in logs:
                log.close()


if __name__ == "__main__":
    main()
