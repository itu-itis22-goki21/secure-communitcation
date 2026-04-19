# secure-communitcation

BLG 478E network security homework for secure communication between Alice and Bob using a Key Distribution Center (KDC).

## Docker Run

This repo now includes Docker support so it runs the same on Windows, macOS, and Linux without local OpenSSL setup.

### Requirements

- Docker Desktop or Docker Engine
- Docker Compose v2

### Start The Demo

From the project directory:

```bash
docker compose up --build
```

You should see logs from:

1. `kdc`
2. `bob`
3. `alice`

When Bob prints `Verification Successful`, the message exchange has completed.

Stop the containers with `Ctrl+C`, then remove them with:

```bash
docker compose down
```

## Notes

- Inside Docker, Alice connects to the `kdc` and `bob` service names instead of `127.0.0.1`.
- Alice retries connections automatically for a few seconds while the server containers start up.
