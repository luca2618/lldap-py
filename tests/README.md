# Tests

## Prereqs
- Docker (with Compose)
- Python 3.8+ and pip

## Run
1. Generate certs:
   - `mkdir -p tests/certs`
   - `openssl req -x509 -newkey rsa:2048 -keyout tests/certs/lldap.key -out tests/certs/lldap.crt -days 365 -nodes -subj /CN=localhost`
   - `openssl req -x509 -newkey rsa:2048 -keyout tests/certs/proxy.key -out tests/certs/proxy.crt -days 365 -nodes -subj /CN=localhost`
   - `chmod 644 tests/certs/lldap.key tests/certs/lldap.crt tests/certs/proxy.key tests/certs/proxy.crt`
2. From the repo root, start services:
   - `docker compose -f tests/docker-compose.yml up -d`
3. Install deps:
   - `pip install -r requirements.txt`
   - `pip install .`
4. Run tests:
   - `pytest tests/ -v`

