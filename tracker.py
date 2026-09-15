import argparse
import json
import socket
import threading
import time
from typing import Dict, Tuple


PEERS_LOCK = threading.Lock()
PEERS: Dict[str, Dict[str, object]] = {}


def send_json(conn: socket.socket, payload: dict) -> None:
    data = (json.dumps(payload) + "\n").encode("utf-8")
    conn.sendall(data)


def read_json_line(conn: socket.socket) -> dict:
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("Connection closed")
        buf += chunk
    line, _, _rest = buf.partition(b"\n")
    return json.loads(line.decode("utf-8"))


def cleanup_stale_peers(ttl_seconds: int) -> None:
    while True:
        now = time.time()
        with PEERS_LOCK:
            stale_ids = [
                peer_id
                for peer_id, meta in PEERS.items()
                if now - float(meta["last_seen"]) > ttl_seconds
            ]
            for peer_id in stale_ids:
                del PEERS[peer_id]
        time.sleep(max(2, ttl_seconds // 2))


def handle_client(conn: socket.socket, addr: Tuple[str, int]) -> None:
    try:
        request = read_json_line(conn)
        action = request.get("action")

        if action == "register":
            peer_id = request["peer_id"]
            listen_port = int(request["listen_port"])
            advertised_ip = request.get("public_ip") or addr[0]
            with PEERS_LOCK:
                PEERS[peer_id] = {
                    "ip": advertised_ip,
                    "port": listen_port,
                    "last_seen": time.time(),
                }
            send_json(conn, {"ok": True, "message": "registered"})
            return

        if action == "list":
            with PEERS_LOCK:
                peers = {
                    peer_id: {
                        "ip": str(meta["ip"]),
                        "port": int(meta["port"]),
                        "last_seen": float(meta["last_seen"]),
                    }
                    for peer_id, meta in PEERS.items()
                }
            send_json(conn, {"ok": True, "peers": peers})
            return

        if action == "heartbeat":
            peer_id = request["peer_id"]
            with PEERS_LOCK:
                if peer_id in PEERS:
                    PEERS[peer_id]["last_seen"] = time.time()
                    send_json(conn, {"ok": True})
                else:
                    send_json(conn, {"ok": False, "error": "peer not registered"})
            return

        send_json(conn, {"ok": False, "error": "unknown action"})
    except Exception as exc:  # noqa: BLE001
        try:
            send_json(conn, {"ok": False, "error": str(exc)})
        except Exception:
            pass
    finally:
        conn.close()


def run_tracker(host: str, port: int, ttl_seconds: int) -> None:
    cleaner = threading.Thread(target=cleanup_stale_peers, args=(ttl_seconds,), daemon=True)
    cleaner.start()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(128)
        print(f"[tracker] listening on {host}:{port}")
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple P2P tracker (matchmaking only).")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9000)
    parser.add_argument("--ttl", type=int, default=30, help="peer timeout in seconds")
    args = parser.parse_args()
    run_tracker(args.host, args.port, args.ttl)


if __name__ == "__main__":
    main()
