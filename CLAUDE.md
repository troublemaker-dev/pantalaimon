# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Pantalaimon is an E2E encryption-aware Matrix reverse proxy daemon. It sits between Matrix clients and a homeserver, transparently encrypting outgoing messages and decrypting incoming ones. Clients connect to pantalaimon as if it were the homeserver; pantalaimon handles all crypto via `matrix-nio[e2e]`, which requires the `libolm` C library (>= 3.1) to be installed.

## Commands

```bash
# Install (requires libolm system library)
pip install .[ui]

# Run tests
python3 -m pytest

# Run a single test file or test
python3 -m pytest tests/proxy_test.py
python3 -m pytest tests/proxy_test.py::TestClass::test_name

# Lint and style checks
python3 -m pytest --flake8 pantalaimon
python3 -m pytest --black pantalaimon

# Type check
mypy --ignore-missing-imports pantalaimon

# Coverage
python3 -m pytest --cov=pantalaimon --cov-report term-missing

# Format
black pantalaimon/
isort -y -p pantalaimon

# Run locally
python -m pantalaimon.main --log-level debug --config ./contrib/pantalaimon.conf
```

## Docker

The image includes the `[ui]` extras (`pydbus`, `PyGObject`, `dbus-python`) so that `panctl` works inside the container. Because those packages make `UI_ENABLED = True`, the daemon requires a D-Bus session bus. `entrypoint.sh` starts `dbus-daemon` at a fixed socket path before exec-ing `pantalaimon`, and `DBUS_SESSION_BUS_ADDRESS` is baked into the image so any exec'd process (including `panctl`) finds the bus automatically.

```bash
# Build
docker build -t pantalaimon .

# Run (create pantalaimon.conf first; UseKeyring = False required in containers)
docker run -it --rm -v /path/to/data:/data -p 8008:8008 pantalaimon

# Use panctl inside a running container
docker exec -it <container> panctl
```

The builder stage requires `libdbus-1-dev libglib2.0-dev libgirepository-2.0-dev libcairo2-dev` to compile the UI Python extensions. The runtime stage requires `libgirepository-2.0-0 gir1.2-glib-2.0 libdbus-1-3 dbus`.

## Architecture

### Threading model

The daemon runs on a single asyncio event loop. When the optional D-Bus UI is enabled (`ui.py`, requires `gi`/`pydbus`), it runs in a separate thread via `GlibT`. The two sides communicate through a pair of `janus.Queue` instances (which bridge sync and async): `pan_queue` carries messages from the UI thread to the daemon, `ui_queue` carries signals from the daemon to the UI thread. The `message_router` coroutine in `main.py` dispatches incoming UI messages to the correct `ProxyDaemon` instance.

### Request flow

```
Matrix client → ProxyDaemon (aiohttp, daemon.py)
                    ↓ intercepts select routes
                PanClient (client.py, matrix-nio AsyncClient)
                    ↓ background sync loop
                Matrix homeserver
```

`ProxyDaemon` (`daemon.py`) handles all HTTP requests. It maintains one `PanClient` per logged-in user in `pan_clients`. Most requests are forwarded directly to the homeserver; the proxy intercepts:
- `login` — starts a `PanClient` background sync loop for the user
- `sync` — decrypts encrypted events in the response before returning them
- `rooms/{room_id}/messages` — same decryption treatment for paginated history
- `rooms/{room_id}/send` — encrypts outgoing messages for encrypted rooms; holds the request if there are unverified devices and signals the UI thread
- `media/upload` — encrypts uploaded files and stores encryption keys
- `media/download` — fetches and decrypts previously encrypted files
- `search` — optionally handled locally by the tantivy index (currently disabled)

### Key components

- **`daemon.py` — `ProxyDaemon`**: The aiohttp request handler. Owns the per-user `PanClient` map. Sends/receives `thread_messages` to communicate with the UI. Handles the unverified-devices flow (semaphore + decision queue per room).

- **`client.py` — `PanClient`**: Subclass of `nio.AsyncClient`. Runs a continuous background sync loop. Handles SAS key verification, key request forwarding, and optional room history indexing. The `synced` asyncio `Event` is used in `daemon.py` to wait for a new sync when decryption fails.

- **`store.py` — `PanStore`**: SQLite-backed persistence via peewee. Stores which users belong to which server, access tokens (when keyring is disabled), and encrypted media metadata (`MediaInfo`, `UploadInfo`). `KeyDroppingSqliteStore` is a nio store subclass that drops old Megolm sessions.

- **`thread_messages.py`**: All inter-thread messages are attrs classes. The daemon sends `UnverifiedDevicesSignal`, `InviteSasSignal`, `ShowSasSignal`, `SasDoneSignal`, `DaemonResponse`, and `UpdateUsersMessage`/`UpdateDevicesMessage` to the UI. The UI sends device management and key operation commands back.

- **`ui.py` — `GlibT`**: The optional D-Bus interface, exposed on the session bus so `panctl` can control the daemon. UI is enabled only when `gi`, `gi.repository`, and `pydbus` are all importable.

- **`panctl.py`**: Interactive prompt_toolkit REPL that issues commands over D-Bus. Entry point: `panctl`.

- **`index.py`**: Full-text search via `tantivy`. Currently **always disabled** — the `INDEXING_ENABLED = True` assignment is inside an `if False:` block, so `INDEXING_ENABLED` is always `False`.

- **`config.py`**: INI-style config (`configparser`) with a `[Default]` section and per-server sections. Default listen address is `localhost:8009`.

### Access token handling

On login the proxy captures the homeserver's response, stores the access token either in the OS keyring (`keyring` library) or in SQLite (if `UseKeyring = False`). Subsequent requests from any client using a valid token are resolved to the owning `PanClient` via `_find_client`, which calls `/_matrix/client/r0/whoami` on first sight and caches the result.

### Media encryption

Uploaded files are encrypted by `PanClient.upload` and the encryption keys (`key`, `iv`, `hashes`) are stored in `PanStore`. On download, `ProxyDaemon._load_decrypted_file` retrieves keys, downloads the ciphertext, and decrypts in a `ProcessPoolExecutor` (to avoid blocking the event loop).
