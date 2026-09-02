# Security Policy

## Reporting a vulnerability

Please report security issues privately to **security@whisper.security**. Do not
open a public issue for a suspected vulnerability.

Include what you found, how to reproduce it, and the impact you expect. We aim to
acknowledge within a few business days and will keep you updated as we work on a
fix. Coordinated disclosure is appreciated.

## Scope

This repository is the **Python client** for Whisper: the control plane
(`whisper.agents`), the keyless public checks, and the Whisper security graph. It
talks only to Whisper's public endpoints and holds no server-side secrets.

Your API key travels in one place and one place only: the `X-API-Key` request
header. It is never written to a URL, a request body, a log line, or argv. A call
made without a key sends no auth header at all rather than an empty one. Any
deviation from that is a security bug and is in scope, as are the input validation
and the redaction of keys from error text.

## Supported versions

The latest published release receives security fixes. Older versions may not.
