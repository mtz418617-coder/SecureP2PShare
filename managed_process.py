import subprocess
import threading
from typing import Optional


class ManagedProcess:
    def __init__(self, name: str, command: list[str], log_callback):
        self.name = name
        self.command = command
        self.log_callback = log_callback
        self.proc: Optional[subprocess.Popen] = None
        self.reader_thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.log_callback(f"[{self.name}] already running")
            return
        self.log_callback(f"[{self.name}] starting: {' '.join(self.command)}")
        self.proc = subprocess.Popen(
            self.command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        self.reader_thread = threading.Thread(target=self._read_output, daemon=True)
        self.reader_thread.start()

    def _read_output(self) -> None:
        assert self.proc is not None
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.log_callback(f"[{self.name}] {line.rstrip()}")
        code = self.proc.poll()
        self.log_callback(f"[{self.name}] exited with code {code}")

    def send(self, text: str) -> None:
        if not self.proc or self.proc.poll() is not None:
            self.log_callback(f"[{self.name}] not running")
            return
        assert self.proc.stdin is not None
        self.proc.stdin.write(text + "\n")
        self.proc.stdin.flush()
        self.log_callback(f"[{self.name}] > {text}")

    def stop(self) -> None:
        if not self.proc or self.proc.poll() is not None:
            self.log_callback(f"[{self.name}] not running")
            return
        self.log_callback(f"[{self.name}] stopping...")
        self.proc.terminate()
