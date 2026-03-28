# Don't Blame The Network (DBTN)

A self-hosted network diagnostic and inventory tool built with Django.

## Features

- **ICMP Scan** — ping sweep with optional reverse DNS and NetBIOS name resolution
- **Bulk ICMP Scan** — scan multiple networks simultaneously with live streaming results
- **Inventory** — ITIL-aligned CMDB for network devices and servers
- **Authentication Profiles** — securely store SNMP, SSH, and HTTPS credentials (encrypted at rest)
- **User Management** — admin and standard user roles

---

## Quick Start

Requires Docker and Docker Compose.

### 1. Create a working directory

```bash
mkdir dbtn && cd dbtn
```

### 2. Download the example compose file

```bash
curl -o docker-compose.yml https://raw.githubusercontent.com/dlukesimmons/dont-blame-the-network/main/docker-compose.example.yml
```

### 3. Generate required secrets

**Fernet encryption key** (for stored credentials):
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**Django secret key** (random 50-character string):
```bash
python3 -c "import secrets, string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(50)))"
```

### 4. Edit docker-compose.yml

Replace every `CHANGE_ME_*` value with your generated secrets and desired passwords.

> **Important:** Keep a backup of `FIELD_ENCRYPTION_KEY`. If it is lost, stored credentials (SNMP community strings, SSH passwords, API tokens) cannot be decrypted.

### 5. Start

```bash
docker compose up -d
```

The app will be available at `http://<your-host>:8200`.
Default admin login is whatever you set for `DJANGO_SUPERUSER_USERNAME` / `DJANGO_SUPERUSER_PASSWORD`.

---

## Upgrading

```bash
docker compose pull
docker compose up -d
```

Migrations run automatically on startup.

---

## Capabilities Note

The `NET_RAW` and `NET_ADMIN` capabilities are required for nmap to send ICMP packets (ping sweep). These are the minimum permissions needed and are limited to this container.

---

## Development

```bash
git clone https://github.com/dlukesimmons/dont-blame-the-network.git
cd dont-blame-the-network
docker compose up -d
```

The dev `docker-compose.yml` builds the image locally. Any changes require a rebuild:

```bash
docker compose build && docker compose up -d
```
