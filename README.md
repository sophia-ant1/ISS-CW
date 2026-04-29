# Secure Learning System

Python coursework project implementing:
- Argon2id password hashing
- AES-256-GCM encryption
- ECDH key agreement
- ECDSA P-256 digital signatures
- HMAC-SHA256 integrity checks
- Envelope encryption using Python `secrets`
- ES256JWT session management with PyJWT
- Role-based access control for student, lecturer, and admin

## Run

```bash
python main.py
```

Runs an end-to-end demo.

```bash
python main.py --interactive
```

Runs an interactive console mode for screenshots.

## Test

```bash
python -m unittest tests.test_cases
```
