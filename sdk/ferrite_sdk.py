"""Ferrite extension protocol v1. Standard-library-only binary-safe hooks."""
from dataclasses import dataclass
import base64
import json
import sys

VERSION = 1
MAX_MESSAGE = 2 * 1024 * 1024

@dataclass(frozen=True)
class Message:
    phase: str
    url: str
    raw: bytes

def receive(stream=None):
    data = (stream or sys.stdin.buffer).read(MAX_MESSAGE + 1)
    if len(data) > MAX_MESSAGE:
        raise ValueError("Input exceeds 2 MiB")
    value = json.loads(data)
    if value.get("version") != VERSION or value.get("phase") not in ("request", "response"):
        raise ValueError("Unsupported Ferrite protocol")
    return Message(value["phase"], value["url"], base64.b64decode(value["raw_base64"], validate=True))

def send(raw, stream=None):
    data = json.dumps({"version": VERSION, "raw_base64": base64.b64encode(raw).decode("ascii")}).encode()
    if len(data) >= MAX_MESSAGE:
        raise ValueError("Output exceeds 2 MiB")
    (stream or sys.stdout.buffer).write(data + b"\n")
