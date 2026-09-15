import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import hashlib
import hmac
import json
import os
import socket
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from file_crypto import decrypt_file_hybrid


CHUNK_SIZE = 64 * 1024

# (peer_id, host, port, transport_encrypted: True/False if peer advertises, None if unknown/legacy)
SourcePeer = Tuple[str, str, int, Optional[bool]]


def xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def derive_transport_key(psk: str) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", psk.encode("utf-8"), b"nasus-p2p-salt", 120_000, dklen=32)


def stream_encrypt(plaintext: bytes, key: bytes) -> bytes:
    nonce = os.urandom(16)
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(plaintext):
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        keystream.extend(block)
        counter += 1
    ciphertext = xor_bytes(plaintext, bytes(keystream[: len(plaintext)]))
    mac = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    return nonce + ciphertext + mac


def stream_decrypt(blob: bytes, key: bytes) -> bytes:
    if len(blob) < 16 + 32:
        raise ValueError("encrypted payload too short")
    nonce = blob[:16]
    mac = blob[-32:]
    ciphertext = blob[16:-32]
    expected = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected):
        raise ValueError("message authentication failed")
    keystream = bytearray()
    counter = 0
    while len(keystream) < len(ciphertext):
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        keystream.extend(block)
        counter += 1
    return xor_bytes(ciphertext, bytes(keystream[: len(ciphertext)]))


def send_json(sock: socket.socket, payload: dict) -> None:
    sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))


def recv_json(sock: socket.socket) -> dict:
    data = b""
    while b"\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    line, _, _rest = data.partition(b"\n")
    return json.loads(line.decode("utf-8"))


def request_tracker(tracker_host: str, tracker_port: int, payload: dict) -> dict:
    with socket.create_connection((tracker_host, tracker_port), timeout=5) as sock:
        send_json(sock, payload)
        return recv_json(sock)


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def chunk_hashes(path: Path) -> List[str]:
    hashes: List[str] = []
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            hashes.append(hashlib.sha256(chunk).hexdigest())
    return hashes


def _fresh_peer_stats(lat_ms: float) -> Dict[str, float]:
    return {"ok": 0.0, "fail": 0.0, "bytes": 0.0, "lat_ema_ms": lat_ms, "integrity_fail": 0.0}


class PeerNode:
    def __init__(
        self,
        peer_id: str,
        listen_host: str,
        listen_port: int,
        tracker_host: str,
        tracker_port: int,
        public_ip: Optional[str],
        psk: Optional[str],
        trusted_peer_ids: Optional[Set[str]] = None,
    ) -> None:
        self.peer_id = peer_id
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.tracker_host = tracker_host
        self.tracker_port = tracker_port
        self.public_ip = public_ip
        self.shared_files: Dict[str, Path] = {}
        self.running = True
        self.crypto_key = derive_transport_key(psk) if psk else None
        self.trusted_peer_ids: Optional[Set[str]] = trusted_peer_ids
        self.peer_stats: Dict[str, Dict[str, float]] = {}
        self.stats_lock = threading.Lock()

    def register(self) -> None:
        payload = {
            "action": "register",
            "peer_id": self.peer_id,
            "listen_port": self.listen_port,
            "public_ip": self.public_ip,
        }
        res = request_tracker(self.tracker_host, self.tracker_port, payload)
        if not res.get("ok"):
            raise RuntimeError(f"register failed: {res}")

    def heartbeat_loop(self) -> None:
        while self.running:
            try:
                request_tracker(
                    self.tracker_host,
                    self.tracker_port,
                    {"action": "heartbeat", "peer_id": self.peer_id},
                )
            except Exception:
                pass
            time.sleep(5)

    def list_peers(self) -> dict:
        res = request_tracker(self.tracker_host, self.tracker_port, {"action": "list"})
        if not res.get("ok"):
            raise RuntimeError(f"list failed: {res}")
        return res["peers"]

    def server_loop(self) -> None:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.listen_host, self.listen_port))
            srv.listen(64)
            print(f"[peer:{self.peer_id}] listening on {self.listen_host}:{self.listen_port}")
            while self.running:
                conn, addr = srv.accept()
                t = threading.Thread(target=self.handle_incoming, args=(conn, addr), daemon=True)
                t.start()

    def handle_incoming(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        try:
            req = recv_json(conn)
            action = req.get("action")
            if action == "list_files":
                files_meta = {}
                for name, p in self.shared_files.items():
                    files_meta[name] = {
                        "size": p.stat().st_size,
                        "chunk_size": CHUNK_SIZE,
                        "chunk_hashes": chunk_hashes(p),
                        "file_hash": file_sha256(p),
                        "transport_encrypted": self.crypto_key is not None,
                    }
                send_json(conn, {"ok": True, "files": files_meta})
                return

            if action == "get_chunk":
                filename = req["filename"]
                idx = int(req["index"])
                if filename not in self.shared_files:
                    send_json(conn, {"ok": False, "error": "file not found"})
                    return
                path = self.shared_files[filename]
                with path.open("rb") as f:
                    f.seek(idx * CHUNK_SIZE)
                    data = f.read(CHUNK_SIZE)
                payload = data
                encrypted = False
                if self.crypto_key is not None:
                    payload = stream_encrypt(data, self.crypto_key)
                    encrypted = True
                send_json(
                    conn,
                    {
                        "ok": True,
                        "index": idx,
                        "size": len(payload),
                        "encrypted": encrypted,
                        "chunk_hash": hashlib.sha256(data).hexdigest(),
                    },
                )
                conn.sendall(payload)
                return

            send_json(conn, {"ok": False, "error": "unknown action"})
        except Exception as exc:  # noqa: BLE001
            try:
                send_json(conn, {"ok": False, "error": str(exc)})
            except Exception:
                pass
        finally:
            conn.close()

    def add_share(self, file_path: str) -> None:
        path = Path(file_path).resolve()
        if not path.exists() or not path.is_file():
            raise FileNotFoundError(path)
        self.shared_files[path.name] = path
        print(f"[share] {path.name} ({path.stat().st_size} bytes)")

    def peer_files(self, host: str, port: int) -> dict:
        with socket.create_connection((host, port), timeout=8) as sock:
            send_json(sock, {"action": "list_files"})
            response = recv_json(sock)
        if not response.get("ok"):
            raise RuntimeError(response.get("error", "list_files failed"))
        return response["files"]

    def _record_peer_probe(self, peer_id: str, latency_ms: float) -> None:
        with self.stats_lock:
            stats = self.peer_stats.setdefault(peer_id, _fresh_peer_stats(latency_ms))
            stats["lat_ema_ms"] = (0.85 * stats["lat_ema_ms"]) + (0.15 * latency_ms)

    def _fetch_chunk_once(
        self,
        peer_id: str,
        host: str,
        port: int,
        filename: str,
        idx: int,
        expected_chunk_hash: str,
    ) -> bytes:
        started = time.time()
        with socket.create_connection((host, port), timeout=8) as sock:
            send_json(sock, {"action": "get_chunk", "filename": filename, "index": idx})
            meta = recv_json(sock)
            if not meta.get("ok"):
                raise RuntimeError(meta.get("error", "get_chunk failed"))
            size = int(meta["size"])
            data = b""
            while len(data) < size:
                packet = sock.recv(size - len(data))
                if not packet:
                    raise ConnectionError("incomplete chunk")
                data += packet
        if meta.get("encrypted"):
            if self.crypto_key is None:
                raise RuntimeError("peer sent encrypted chunk but no --psk configured")
            try:
                data = stream_decrypt(data, self.crypto_key)
            except ValueError as exc:
                if "authentication" in str(exc).lower():
                    self._record_peer_integrity_failure(peer_id)
                else:
                    self._record_peer_failure(peer_id)
                raise
        got = hashlib.sha256(data).hexdigest()
        if got != expected_chunk_hash:
            self._record_peer_integrity_failure(peer_id)
            raise RuntimeError(f"chunk {idx} hash mismatch")
        elapsed_ms = (time.time() - started) * 1000
        self._record_peer_success(peer_id, len(data), elapsed_ms)
        return data

    def _record_peer_success(self, peer_id: str, bytes_count: int, latency_ms: float) -> None:
        with self.stats_lock:
            stats = self.peer_stats.setdefault(peer_id, _fresh_peer_stats(latency_ms))
            stats["ok"] += 1
            stats["bytes"] += float(bytes_count)
            stats["lat_ema_ms"] = (0.85 * stats["lat_ema_ms"]) + (0.15 * latency_ms)

    def _record_peer_failure(self, peer_id: str) -> None:
        with self.stats_lock:
            stats = self.peer_stats.setdefault(peer_id, _fresh_peer_stats(500.0))
            stats["fail"] += 1

    def _record_peer_integrity_failure(self, peer_id: str) -> None:
        with self.stats_lock:
            stats = self.peer_stats.setdefault(peer_id, _fresh_peer_stats(500.0))
            stats["integrity_fail"] += 1

    def _peer_selection_score(self, peer_id: str, transport_encrypted: Optional[bool]) -> float:
        """Rank peers for automatic source selection: past transfer quality + transport safety."""
        with self.stats_lock:
            if self.trusted_peer_ids and peer_id not in self.trusted_peer_ids:
                return -1e9
            stats = self.peer_stats.get(peer_id)
            if not stats:
                ml = 0.5
                integrity_rate = 0.0
            else:
                integ = stats.get("integrity_fail", 0.0)
                total = stats["ok"] + stats["fail"] + integ
                success_rate = stats["ok"] / total if total else 0.0
                failure_rate = stats["fail"] / total if total else 0.0
                integrity_rate = integ / total if total else 0.0
                latency_penalty = min(1.0, stats["lat_ema_ms"] / 2000.0)
                throughput_bonus = min(1.0, stats["bytes"] / (8 * 1024 * 1024))
                ml = (
                    (0.75 * success_rate)
                    - (0.85 * failure_rate)
                    - (0.35 * latency_penalty)
                    + (0.25 * throughput_bonus)
                )
            score = ml - (1.1 * integrity_rate)
            if self.crypto_key is not None:
                if transport_encrypted is True:
                    score += 0.35
                elif transport_encrypted is False:
                    score -= 0.85
            return score

    def select_best_source_for_file(self, filename: str) -> Tuple[str, str, int]:
        sources, _ = self._discover_sources(filename)
        scored = sorted(sources, key=lambda s: self._peer_selection_score(s[0], s[3]), reverse=True)
        if not scored:
            raise RuntimeError(f"no online source peers for '{filename}'")
        best_peer_id, host, port, enc = scored[0]
        score = self._peer_selection_score(best_peer_id, enc)
        enc_s = "unknown" if enc is None else str(enc)
        print(f"[peer] auto-selected source {best_peer_id} score={score:.3f} (transport_encrypted={enc_s})")
        return best_peer_id, host, port

    def download_file_best(self, filename: str, out_dir: str = "downloads") -> Path:
        peer_id, _, _ = self.select_best_source_for_file(filename)
        return self.download_file(peer_id, filename, out_dir)

    def download_file(self, src_peer_id: str, filename: str, out_dir: str = "downloads") -> Path:
        peers = self.list_peers()
        if src_peer_id not in peers:
            raise RuntimeError(f"peer '{src_peer_id}' not found")
        info = peers[src_peer_id]
        host, port = info["ip"], int(info["port"])

        files = self.peer_files(host, port)
        if filename not in files:
            raise RuntimeError(f"'{filename}' not shared by {src_peer_id}")
        file_info = files[filename]
        expected_hashes: List[str] = file_info["chunk_hashes"]
        target_hash = file_info["file_hash"]

        os.makedirs(out_dir, exist_ok=True)
        out_path = Path(out_dir) / filename
        with out_path.open("wb") as out:
            for idx, expected_chunk_hash in enumerate(expected_hashes):
                data = self._fetch_chunk_once(src_peer_id, host, port, filename, idx, expected_chunk_hash)
                out.write(data)
                print(f"[download] chunk {idx + 1}/{len(expected_hashes)} ok")

        final_hash = file_sha256(out_path)
        if final_hash != target_hash:
            raise RuntimeError("final file hash mismatch")
        print(f"[download] complete: {out_path}")
        return out_path

    def _discover_sources(self, filename: str) -> Tuple[List[SourcePeer], dict]:
        peers = self.list_peers()
        sources: List[SourcePeer] = []
        canonical_info: Optional[dict] = None

        for peer_id, info in peers.items():
            if peer_id == self.peer_id:
                continue
            host, port = info["ip"], int(info["port"])
            try:
                start = time.time()
                files = self.peer_files(host, port)
                latency_ms = (time.time() - start) * 1000
                self._record_peer_probe(peer_id, latency_ms)
            except Exception:
                continue
            if filename not in files:
                continue
            candidate = files[filename]
            _te = candidate.get("transport_encrypted")
            encrypted: Optional[bool] = None if _te is None else bool(_te)
            if canonical_info is None:
                canonical_info = candidate
                sources.append((peer_id, host, port, encrypted))
                continue
            if (
                candidate.get("file_hash") == canonical_info.get("file_hash")
                and candidate.get("chunk_hashes") == canonical_info.get("chunk_hashes")
            ):
                sources.append((peer_id, host, port, encrypted))

        if canonical_info is None or not sources:
            raise RuntimeError(f"no online source peers for '{filename}'")
        return sources, canonical_info

    def _fetch_chunk_with_fallback(
        self,
        filename: str,
        idx: int,
        expected_chunk_hash: str,
        preferred_source_index: int,
        sources: List[SourcePeer],
    ) -> Tuple[int, bytes, str]:
        scored = sorted(sources, key=lambda s: self._peer_selection_score(s[0], s[3]), reverse=True)
        rotated = scored[preferred_source_index:] + scored[:preferred_source_index]
        errors: List[str] = []
        for peer_id, host, port, _enc in rotated:
            try:
                data = self._fetch_chunk_once(peer_id, host, port, filename, idx, expected_chunk_hash)
                return idx, data, peer_id
            except Exception as exc:  # noqa: BLE001
                msg = str(exc).lower()
                if (
                    "hash mismatch" not in msg
                    and "authentication failed" not in msg
                    and "message authentication" not in msg
                ):
                    self._record_peer_failure(peer_id)
                errors.append(f"{peer_id}@{host}:{port} -> {exc}")
                continue
        raise RuntimeError(f"chunk {idx} failed on all sources: {' | '.join(errors)}")

    def download_file_swarm(self, filename: str, out_dir: str = "downloads", max_workers: int = 6) -> Path:
        sources, file_info = self._discover_sources(filename)
        expected_hashes: List[str] = file_info["chunk_hashes"]
        target_hash = file_info["file_hash"]
        chunk_total = len(expected_hashes)
        print(f"[swarm] sources={len(sources)} chunks={chunk_total}")

        os.makedirs(out_dir, exist_ok=True)
        out_path = Path(out_dir) / filename
        chunks: List[Optional[bytes]] = [None] * chunk_total
        completed = 0

        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, chunk_total))) as executor:
            futures = []
            for idx, chunk_hash in enumerate(expected_hashes):
                preferred_source_index = idx % len(sources)
                futures.append(
                    executor.submit(
                        self._fetch_chunk_with_fallback,
                        filename,
                        idx,
                        chunk_hash,
                        preferred_source_index,
                        sources,
                    )
                )

            for future in as_completed(futures):
                idx, data, peer_id = future.result()
                chunks[idx] = data
                completed += 1
                print(f"[swarm] chunk {completed}/{chunk_total} from {peer_id}")

        with out_path.open("wb") as out:
            for idx, data in enumerate(chunks):
                if data is None:
                    raise RuntimeError(f"missing chunk {idx}")
                out.write(data)

        final_hash = file_sha256(out_path)
        if final_hash != target_hash:
            raise RuntimeError("final file hash mismatch")
        print(f"[swarm] complete: {out_path}")
        return out_path

    def decrypt_downloaded_file(
        self,
        encrypted_path: Path,
        password: str,
        out_path: Optional[Path] = None,
    ) -> Path:
        if out_path is None:
            if encrypted_path.suffix == ".enc":
                out_path = encrypted_path.with_suffix("")
            else:
                out_path = encrypted_path.with_name(encrypted_path.name + ".decrypted")
        from file_crypto import decrypt_bytes as decrypt_file_bytes
        from file_crypto import derive_key as derive_file_key

        plaintext = decrypt_file_bytes(encrypted_path.read_bytes(), derive_file_key(password))
        out_path.write_bytes(plaintext)
        print(f"[decrypt] complete: {out_path}")
        return out_path

    def decrypt_downloaded_file_rsa(
        self,
        encrypted_path: Path,
        private_key_path: str,
        out_path: Optional[Path] = None,
    ) -> Path:
        if out_path is None:
            if encrypted_path.suffix == ".enc":
                out_path = encrypted_path.with_suffix("")
            else:
                out_path = encrypted_path.with_name(encrypted_path.name + ".decrypted")
        decrypt_file_hybrid(encrypted_path, out_path, Path(private_key_path).resolve())
        print(f"[decrypt-rsa] complete: {out_path}")
        return out_path


def _parse_trusted_peers(raw: Optional[str]) -> Optional[Set[str]]:
    if raw is None or not str(raw).strip():
        return None
    return {p.strip() for p in str(raw).split(",") if p.strip()}


def run_cli(args: argparse.Namespace) -> None:
    node = PeerNode(
        peer_id=args.peer_id,
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        tracker_host=args.tracker_host,
        tracker_port=args.tracker_port,
        public_ip=args.public_ip,
        psk=args.psk,
        trusted_peer_ids=_parse_trusted_peers(args.trusted_peers),
    )
    node.register()

    if args.share:
        for path in args.share:
            node.add_share(path)

    server_thread = threading.Thread(target=node.server_loop, daemon=True)
    hb_thread = threading.Thread(target=node.heartbeat_loop, daemon=True)
    server_thread.start()
    hb_thread.start()

    print(
        "[cmd] peers | files <peer_id> | get <filename> (auto) | get <peer_id> <filename> | "
        "best <filename> | getdec <filename.enc> <password> (auto) | "
        "getdec <peer_id> <filename.enc> <password> | "
        "getdec_rsa <filename.enc> <private_key.pem> (auto) | "
        "getdec_rsa <peer_id> <filename.enc> <private_key.pem> | "
        "swarm <filename> [workers] | "
        "swarmdec <filename.enc> <password> [workers] | "
        "swarmdec_rsa <filename.enc> <private_key.pem> [workers] | quit"
    )
    while True:
        try:
            command = input("> ").strip()
        except (KeyboardInterrupt, EOFError):
            command = "quit"

        if command == "quit":
            node.running = False
            break

        if command == "peers":
            print(node.list_peers())
            continue

        parts = command.split()
        if len(parts) == 2 and parts[0] == "files":
            src_peer = parts[1]
            peers = node.list_peers()
            if src_peer not in peers:
                print("peer not found")
                continue
            host, port = peers[src_peer]["ip"], int(peers[src_peer]["port"])
            with socket.create_connection((host, port), timeout=8) as sock:
                send_json(sock, {"action": "list_files"})
                print(recv_json(sock))
            continue

        if len(parts) >= 2 and parts[0] == "get":
            peers_map = node.list_peers()
            if len(parts) >= 3 and parts[1] in peers_map:
                src_peer = parts[1]
                filename = " ".join(parts[2:])
                try:
                    node.download_file(src_peer, filename)
                except Exception as exc:  # noqa: BLE001
                    print(f"error: {exc}")
            else:
                filename = " ".join(parts[1:])
                try:
                    node.download_file_best(filename)
                except Exception as exc:  # noqa: BLE001
                    print(f"error: {exc}")
            continue

        if len(parts) >= 3 and parts[0] == "getdec":
            peers_map = node.list_peers()
            if len(parts) >= 4 and parts[1] in peers_map:
                src_peer = parts[1]
                filename = parts[2]
                password = " ".join(parts[3:])
                try:
                    encrypted_path = node.download_file(src_peer, filename)
                    node.decrypt_downloaded_file(encrypted_path, password)
                except Exception as exc:  # noqa: BLE001
                    print(f"error: {exc}")
            else:
                filename = parts[1]
                password = " ".join(parts[2:])
                try:
                    encrypted_path = node.download_file_best(filename)
                    node.decrypt_downloaded_file(encrypted_path, password)
                except Exception as exc:  # noqa: BLE001
                    print(f"error: {exc}")
            continue

        if len(parts) >= 3 and parts[0] == "getdec_rsa":
            peers_map = node.list_peers()
            if len(parts) >= 4 and parts[1] in peers_map:
                src_peer = parts[1]
                filename = parts[2]
                private_key_path = " ".join(parts[3:])
                try:
                    encrypted_path = node.download_file(src_peer, filename)
                    node.decrypt_downloaded_file_rsa(encrypted_path, private_key_path)
                except Exception as exc:  # noqa: BLE001
                    print(f"error: {exc}")
            else:
                filename = parts[1]
                private_key_path = " ".join(parts[2:])
                try:
                    encrypted_path = node.download_file_best(filename)
                    node.decrypt_downloaded_file_rsa(encrypted_path, private_key_path)
                except Exception as exc:  # noqa: BLE001
                    print(f"error: {exc}")
            continue

        if len(parts) >= 2 and parts[0] == "best":
            filename = " ".join(parts[1:])
            try:
                node.download_file_best(filename)
            except Exception as exc:  # noqa: BLE001
                print(f"error: {exc}")
            continue

        if len(parts) >= 2 and parts[0] == "swarm":
            filename = parts[1]
            workers = 6
            if len(parts) >= 3:
                try:
                    workers = int(parts[2])
                except ValueError:
                    print("workers must be an integer")
                    continue
            try:
                node.download_file_swarm(filename, max_workers=workers)
            except Exception as exc:  # noqa: BLE001
                print(f"error: {exc}")
            continue

        if len(parts) >= 3 and parts[0] == "swarmdec":
            filename = parts[1]
            password = parts[2]
            workers = 6
            if len(parts) >= 4:
                try:
                    workers = int(parts[3])
                except ValueError:
                    print("workers must be an integer")
                    continue
            try:
                encrypted_path = node.download_file_swarm(filename, max_workers=workers)
                node.decrypt_downloaded_file(encrypted_path, password)
            except Exception as exc:  # noqa: BLE001
                print(f"error: {exc}")
            continue

        if len(parts) >= 3 and parts[0] == "swarmdec_rsa":
            filename = parts[1]
            private_key_path = parts[2]
            workers = 6
            if len(parts) >= 4:
                try:
                    workers = int(parts[3])
                except ValueError:
                    print("workers must be an integer")
                    continue
            try:
                encrypted_path = node.download_file_swarm(filename, max_workers=workers)
                node.decrypt_downloaded_file_rsa(encrypted_path, private_key_path)
            except Exception as exc:  # noqa: BLE001
                print(f"error: {exc}")
            continue

        print("unknown command")


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple torrent-like peer (direct chunk transfer).")
    parser.add_argument("--peer-id", required=True)
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, required=True)
    parser.add_argument("--tracker-host", required=True)
    parser.add_argument("--tracker-port", type=int, default=9000)
    parser.add_argument(
        "--public-ip",
        default=None,
        help="Advertised address for other peers (needed behind NAT, e.g. router public IP).",
    )
    parser.add_argument(
        "--psk",
        default=None,
        help="Shared secret for encrypted peer chunk transfer (all peers should match).",
    )
    parser.add_argument(
        "--trusted-peers",
        default=None,
        help="Comma-separated peer_id list allowed for automatic source selection (default: all hash-verified peers).",
    )
    parser.add_argument("--share", action="append", help="File path to share (repeatable)")
    args = parser.parse_args()
    run_cli(args)


if __name__ == "__main__":
    main()
