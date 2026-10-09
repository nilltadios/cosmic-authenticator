#!/usr/bin/env python3
"""A stand-in for Proton's API, for testing sync without a real account.

    demo/mock-proton.py PORT

Serves the requests the app makes (docs/proton-sync.md) on 127.0.0.1, with
the account key from tests/fixtures. Entry contents stay opaque, as on
Proton's side. Like Proton it checks LastRevision on updates and refuses
expired access tokens until the client refreshes. The first access token,
"access-0", is expired on purpose so every run exercises the refresh.

GET /_state returns the stored keys and entries, in order, for checks.
Run by demo/sync-test.sh; never used against a real account.
"""

import itertools
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
USER_KEY = (FIXTURES / "user-key.asc").read_text()
PAGE_SIZE = 2  # small, so paging with Since is exercised

lock = threading.Lock()
ids = itertools.count(1)
keys = []
entries = []  # in the user's order
valid_tokens = set()
requests = []


def now():
    return int(time.time())


def entry_json(entry):
    return {
        "EntryID": entry["EntryID"],
        "AuthenticatorKeyID": entry["AuthenticatorKeyID"],
        "Revision": entry["Revision"],
        "ContentFormatVersion": 1,
        "Content": entry["Content"],
        "Flags": 0,
        "CreateTime": entry["CreateTime"],
        "ModifyTime": entry["ModifyTime"],
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def handle_any(self, method):
        url = urlparse(self.path)
        path = url.path.removeprefix("/")
        with lock:
            requests.append(f"{method} {path}")
            if path == "_state":
                return self.reply(200, {"Keys": keys, "Entries": entries, "Requests": requests})
            if not self.headers.get("x-pm-appversion", "").startswith("linux-authenticator@"):
                return self.reply(400, {"Code": 5003, "Error": "Missing app version"})
            if path == "auth/v4/refresh":
                token = f"access-{next(ids)}"
                valid_tokens.add(token)
                body = self.body()
                return self.reply(200, {"Code": 1000, "UID": body["UID"], "AccessToken": token,
                                        "RefreshToken": f"refresh-{next(ids)}"})
            auth = self.headers.get("Authorization", "").removeprefix("Bearer ")
            if auth not in valid_tokens:
                return self.reply(401, {"Code": 401, "Error": "Access token expired"})
            return self.route(method, path, parse_qs(url.query))

    def route(self, method, path, query):
        if (method, path) == ("GET", "core/v4/users"):
            return self.reply(200, {"Code": 1000, "User": {"Email": "sync-test@example.invalid", "Keys": [
                {"ID": "user-key-1", "PrivateKey": USER_KEY, "Primary": 1, "Active": 1}]}})
        if (method, path) == ("DELETE", "core/v4/auth"):
            return self.reply(200, {"Code": 1000})
        if (method, path) == ("GET", "authenticator/v1/key"):
            return self.reply(200, {"Code": 1000, "Keys": {"Keys": keys}})
        if (method, path) == ("POST", "authenticator/v1/key"):
            key = {"KeyID": f"auth-key-{next(ids)}", "UserKeyID": "user-key-1", "Key": self.body()["Key"]}
            keys.append(key)
            return self.reply(200, {"Code": 1000, "Key": key})
        if (method, path) == ("GET", "authenticator/v1/entry"):
            since = query.get("Since", [None])[0]
            start = 0
            if since is not None:
                start = next((i + 1 for i, e in enumerate(entries) if e["EntryID"] == since), len(entries))
            page = entries[start:start + PAGE_SIZE]
            last = page[-1]["EntryID"] if page else None
            return self.reply(200, {"Code": 1000, "Entries": {
                "Entries": [entry_json(e) for e in page], "Total": len(entries), "LastID": last}})
        if (method, path) == ("POST", "authenticator/v1/entry/bulk"):
            created = []
            for item in self.body()["Entries"]:
                if item["AuthenticatorKeyID"] not in {k["KeyID"] for k in keys}:
                    return self.reply(422, {"Code": 2501, "Error": "Unknown key"})
                entry = {"EntryID": f"entry-{next(ids)}", "AuthenticatorKeyID": item["AuthenticatorKeyID"],
                         "Revision": 1, "Content": item["Content"], "CreateTime": now(), "ModifyTime": now()}
                entries.append(entry)
                created.append(entry_json(entry))
            return self.reply(200, {"Code": 1000, "Entries": created})
        if (method, path) == ("PUT", "authenticator/v1/entry/bulk"):
            items = self.body()["Entries"]
            by_id = {e["EntryID"]: e for e in entries}
            for item in items:
                entry = by_id.get(item["EntryID"])
                if entry is None:
                    return self.reply(422, {"Code": 2501, "Error": "Entry does not exist"})
                if entry["Revision"] != item["LastRevision"]:
                    return self.reply(409, {"Code": 2511, "Error": "Entry was modified by another client"})
            for item in items:
                entry = by_id[item["EntryID"]]
                entry.update(Content=item["Content"], AuthenticatorKeyID=item["AuthenticatorKeyID"],
                             Revision=entry["Revision"] + 1, ModifyTime=max(now(), entry["ModifyTime"] + 1))
            return self.reply(200, {"Code": 1000, "Entries": [entry_json(by_id[i["EntryID"]]) for i in items]})
        if (method, path) == ("DELETE", "authenticator/v1/entry/bulk"):
            gone = set(self.body()["EntryIDs"])
            entries[:] = [e for e in entries if e["EntryID"] not in gone]
            return self.reply(200, {"Code": 1000})
        if method == "PUT" and path.startswith("authenticator/v1/entry/") and path.endswith("/order"):
            entry_id = path.split("/")[3]
            after = self.body().get("AfterID")
            moving = next((e for e in entries if e["EntryID"] == entry_id), None)
            if moving is None:
                return self.reply(422, {"Code": 2501, "Error": "Entry does not exist"})
            entries.remove(moving)
            position = 0 if after is None else next(i + 1 for i, e in enumerate(entries) if e["EntryID"] == after)
            entries.insert(position, moving)
            return self.reply(200, {"Code": 1000})
        return self.reply(404, {"Code": 404, "Error": f"No route for {method} {path}"})

    def do_GET(self):
        self.handle_any("GET")

    def do_POST(self):
        self.handle_any("POST")

    def do_PUT(self):
        self.handle_any("PUT")

    def do_DELETE(self):
        self.handle_any("DELETE")


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
