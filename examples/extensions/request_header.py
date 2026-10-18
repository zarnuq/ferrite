#!/usr/bin/env python3
"""Run through Ferrite with PYTHONPATH pointing to the repository's sdk directory."""
from ferrite_sdk import receive, send
message = receive()
head, separator, body = message.raw.partition(b"\r\n\r\n")
if separator:
    head += b"\r\nX-Ferrite-Extension: example"
send(head + separator + body)
