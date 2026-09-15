# Simple Torrent-Like P2P (Python)

This is a minimal educational prototype:

- `tracker.py` is only a peer directory (matchmaking).
- `peer.py` transfers file chunks directly peer-to-peer.
- Chunk and full-file integrity are checked with SHA-256.
- Optional encrypted chunk transport with `--psk`.
- Adaptive source selection with a lightweight ML-style peer score.

## Install

Python 3.10+ is enough, no external dependencies.

For RSA + AES hybrid encryption:

```bash
pip install cryptography
```

## GUI (Desktop App)

Run:

```bash
python gui.py
```

What you can do in GUI:

- Start/stop `tracker.py`
- Start/stop peers with `peer.py` options (peer id, ports, share file, PSK)
- Send peer commands from UI (`peers`, `get`, `swarm`, `swarmdec`, etc.)
- Encrypt/decrypt files from buttons (same logic as `file_crypto.py`)
- Generate RSA keys + run RSA/AES hybrid encrypt/decrypt from buttons
- Watch all process logs in one screen

## Run

### 1) Start tracker (publicly reachable machine)

```bash
python tracker.py --host 0.0.0.0 --port 9000
```

### 2) Start uploader peer

```bash
python peer.py ^
  --peer-id alice ^
  --listen-port 5001 ^
  --tracker-host <TRACKER_PUBLIC_IP> ^
  --tracker-port 9000 ^
  --public-ip <ALICE_PUBLIC_IP> ^
  --psk "my-shared-secret" ^
  --share "C:\path\to\file.iso"
```

### 3) Start downloader peer

```bash
python peer.py ^
  --peer-id bob ^
  --listen-port 5002 ^
  --tracker-host <TRACKER_PUBLIC_IP> ^
  --tracker-port 9000 ^
  --public-ip <BOB_PUBLIC_IP> ^
  --psk "my-shared-secret"
```

In Bob console:

- `peers` to list known peers
- `files alice` to list files from Alice
- `get alice file.iso` to download directly from Alice
- `swarm file.iso` to download chunks from all available peers in parallel
- `swarm file.iso 8` same as above but with 8 worker threads
- `getdec alice file.iso.enc mypass` download then decrypt
- `swarmdec file.iso.enc mypass 8` swarm-download then decrypt
- `getdec_rsa alice file.iso.enc private.pem` download then RSA/AES decrypt
- `swarmdec_rsa file.iso.enc private.pem 8` swarm-download then RSA/AES decrypt

## Torrent-like Swarm Behavior

`swarm <filename>` does this:

- asks tracker for all online peers
- probes peers for file metadata
- keeps only peers with matching file hash/chunk hash list
- assigns chunk requests across multiple peers in parallel
- verifies each chunk hash and final file hash before completion
- adapts source preference based on success/failure, latency, and throughput

## Cryptography + ML Notes

- `--psk` enables authenticated encrypted chunk transport between peers.
- If one peer uses `--psk`, all peers should use the same secret.
- Encryption here is educational (stream XOR + HMAC); for production use TLS/Noise/AES-GCM.

## Encrypt/Decrypt Local Files

You can encrypt/decrypt files directly:

```bash
python file_crypto.py encrypt --in "C:\Users\Ahmed\Desktop\SecureP2PShare\test.txt" --out "C:\Users\Ahmed\Desktop\SecureP2PShare\test.txt.enc" --password "ahmed-secret"
python file_crypto.py decrypt --in "C:\Users\Ahmed\Desktop\SecureP2PShare\test.txt.enc" --out "C:\Users\Ahmed\Desktop\SecureP2PShare\test.decrypted.txt" --password "ahmed-secret"
```

RSA + AES-256 hybrid mode:

```bash
python file_crypto.py keygen --private-key "C:\Users\Ahmed\Desktop\SecureP2PShare\private.pem" --public-key "C:\Users\Ahmed\Desktop\SecureP2PShare\public.pem"
python file_crypto.py encrypt-rsa --in "C:\Users\Ahmed\Desktop\SecureP2PShare\test.txt" --out "C:\Users\Ahmed\Desktop\SecureP2PShare\test.txt.enc" --public-key "C:\Users\Ahmed\Desktop\SecureP2PShare\public.pem"
python file_crypto.py decrypt-rsa --in "C:\Users\Ahmed\Desktop\SecureP2PShare\test.txt.enc" --out "C:\Users\Ahmed\Desktop\SecureP2PShare\test.decrypted.txt" --private-key "C:\Users\Ahmed\Desktop\SecureP2PShare\private.pem"
```

Combined with peer transfer:

1) Seed encrypted file (Alice/Charlie share `test.txt.enc`).
2) Bob uses:

```bash
getdec alice test.txt.enc ahmed-secret
swarmdec test.txt.enc ahmed-secret 8
```

## Port Forwarding / NAT

For real internet usage (without Radmin), each peer must be reachable:

- Open/forward the peer listen port (`5001`, `5002`, etc.) on each peer router.
- Allow that port in local firewall.
- Use the correct advertised `--public-ip`.

If peer ports are not reachable, direct P2P download will fail.

## Security Notes

This is not production-safe torrent software. Missing features include:

- authentication / encryption of peer traffic
- DHT, multi-peer parallel download, tit-for-tat, rarest-first scheduling
- NAT traversal techniques (UPnP, STUN/TURN, hole punching)
- abuse protection and peer reputation
