import queue
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from file_crypto import decrypt_file_hybrid, encrypt_file_hybrid, generate_rsa_keypair
from managed_process import ManagedProcess


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("SecureP2PShare GUI")
        self.geometry("1100x760")
        self.resizable(True, True)
        self.configure(bg='#1e1e1e')  # Dark background

        # Apply modern styling
        self.style = ttk.Style()
        self.style.configure('TButton', font=('Arial', 10, 'bold'), padding=6)
        self.style.configure('TLabel', font=('Arial', 10))
        self.style.configure('TEntry', font=('Arial', 10))
        self.style.configure('TNotebook.Tab', font=('Arial', 10, 'bold'))

        self.workspace = Path(__file__).resolve().parent
        self.bg_img: tk.PhotoImage | None = None
        self.log_queue: queue.Queue[str] = queue.Queue()
        self.processes: dict[str, ManagedProcess] = {}

        self._load_background_image()
        self._build_ui()
        self.after(120, self._flush_logs)

    def _load_background_image(self) -> None:
        try:
            self.bg_img = tk.PhotoImage(file=self.workspace / 'background.png')
        except Exception:
            self.bg_img = None


    def _log(self, msg: str) -> None:
        self.log_queue.put(msg)

    def _flush_logs(self) -> None:
        while not self.log_queue.empty():
            msg = self.log_queue.get_nowait()
            self.log_text.configure(state="normal")
            self.log_text.insert("end", msg + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        self.after(120, self._flush_logs)

    def _build_ui(self) -> None:
        if self.bg_img is not None:
            bg_label = tk.Label(self, image=self.bg_img)
            bg_label.place(relx=0, rely=0, relwidth=1, relheight=1)
            bg_label.lower()

        # Header canvas with lock icon/text
        bg_canvas = tk.Canvas(self, bg='#0f0f0f', height=120, highlightthickness=0)
        bg_canvas.pack(fill='x')

        try:
            self.lock_img = tk.PhotoImage(file=self.workspace / 'lock.png')
            bg_canvas.create_image(50, 60, image=self.lock_img, anchor='center')
        except Exception:
            bg_canvas.create_text(50, 60, text='🔒', font=('Arial', 30), fill='white')

        bg_canvas.create_text(550, 60, text='Secure P2P Share', font=('Arial', 26, 'bold'), fill='white')

        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        tracker_tab = tk.Frame(notebook, bg='#1e1e1e')
        peer_tab = tk.Frame(notebook, bg='#1e1e1e')
        crypto_tab = tk.Frame(notebook, bg='#1e1e1e')
        notebook.add(tracker_tab, text="Tracker")
        notebook.add(peer_tab, text="Peer")
        notebook.add(crypto_tab, text="File Crypto")

        self._build_tracker_tab(tracker_tab)
        self._build_peer_tab(peer_tab)
        self._build_crypto_tab(crypto_tab)

        log_frame = tk.LabelFrame(self, text="Process Logs", bg='#1e1e1e', fg='white')
        log_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        
        # Add scrollbar for log text
        scrollbar = ttk.Scrollbar(log_frame)
        scrollbar.pack(side="right", fill="y")
        
        self.log_text = tk.Text(log_frame, height=16, state="disabled", wrap="word", font=('Courier', 9), bg='#1e1e1e', fg='white', yscrollcommand=scrollbar.set)
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)
        scrollbar.config(command=self.log_text.yview)

    def _build_tracker_tab(self, parent: tk.Frame) -> None:
        row = tk.Frame(parent, bg='#1e1e1e')
        row.pack(fill="x", padx=10, pady=10)

        tk.Label(row, text="Host", bg='#1e1e1e', fg='white').grid(row=0, column=0, sticky="w")
        tk.Label(row, text="Port", bg='#1e1e1e', fg='white').grid(row=0, column=2, sticky="w", padx=(12, 0))
        tk.Label(row, text="TTL", bg='#1e1e1e', fg='white').grid(row=0, column=4, sticky="w", padx=(12, 0))

        self.tracker_host = tk.StringVar(value="0.0.0.0")
        self.tracker_port = tk.StringVar(value="9000")
        self.tracker_ttl = tk.StringVar(value="30")

        tk.Entry(row, textvariable=self.tracker_host, width=20, bg='#1e1e1e', fg='white', insertbackground='white').grid(row=0, column=1, sticky="w")
        tk.Entry(row, textvariable=self.tracker_port, width=10, bg='#1e1e1e', fg='white', insertbackground='white').grid(row=0, column=3, sticky="w")
        tk.Entry(row, textvariable=self.tracker_ttl, width=10, bg='#1e1e1e', fg='white', insertbackground='white').grid(row=0, column=5, sticky="w")

        btns = tk.Frame(parent, bg='#1e1e1e')
        btns.pack(fill="x", padx=10, pady=(0, 10))
        tk.Button(btns, text="Start Tracker", command=self.start_tracker, bg='#333333', fg='white').pack(side="left")
        tk.Button(btns, text="Stop Tracker", command=self.stop_tracker, bg='#333333', fg='white').pack(side="left", padx=8)

    def _build_peer_tab(self, parent: tk.Frame) -> None:
        frm = tk.Frame(parent, bg='#1e1e1e')
        frm.pack(fill="x", padx=10, pady=10)

        self.peer_name = tk.StringVar(value="bob")
        self.peer_id = tk.StringVar(value="bob")
        self.peer_listen_host = tk.StringVar(value="0.0.0.0")
        self.peer_listen_port = tk.StringVar(value="5002")
        self.peer_tracker_host = tk.StringVar(value="127.0.0.1")
        self.peer_tracker_port = tk.StringVar(value="9000")
        self.peer_public_ip = tk.StringVar(value="")
        self.peer_share_path = tk.StringVar(value="")

        labels = [
            ("Session Name", self.peer_name),
            ("Peer ID", self.peer_id),
            ("Listen Host", self.peer_listen_host),
            ("Listen Port", self.peer_listen_port),
            ("Tracker Host", self.peer_tracker_host),
            ("Tracker Port", self.peer_tracker_port),
            ("Public IP (optional)", self.peer_public_ip),
        ]

        for idx, (text, var) in enumerate(labels):
            tk.Label(frm, text=text, bg='#1e1e1e', fg='white').grid(row=idx, column=0, sticky="w", pady=2)
            tk.Entry(frm, textvariable=var, width=30, bg='#1e1e1e', fg='white', insertbackground='white').grid(row=idx, column=1, sticky="w", pady=2)

        tk.Label(frm, text="Share File (optional)", bg='#1e1e1e', fg='white').grid(row=8, column=0, sticky="w", pady=2)
        tk.Entry(frm, textvariable=self.peer_share_path, width=55, bg='#1e1e1e', fg='white', insertbackground='white').grid(row=8, column=1, sticky="w", pady=2)
        tk.Button(frm, text="Browse", command=self.pick_share_file, bg='#333333', fg='white').grid(row=8, column=2, padx=8)

        btns = tk.Frame(parent, bg='#1e1e1e')
        btns.pack(fill="x", padx=10, pady=(4, 8))
        tk.Button(btns, text="Start Peer", command=self.start_peer, bg='#333333', fg='white').pack(side="left")
        tk.Button(btns, text="Stop Peer", command=self.stop_peer, bg='#333333', fg='white').pack(side="left", padx=8)

        cmd_row = tk.Frame(parent, bg='#1e1e1e')
        cmd_row.pack(fill="x", padx=10, pady=6)
        tk.Label(cmd_row, text="Peer Command", bg='#1e1e1e', fg='white').pack(side="left")
        self.peer_command = tk.StringVar(value="peers")
        tk.Entry(cmd_row, textvariable=self.peer_command, width=58, bg='#1e1e1e', fg='white', insertbackground='white').pack(side="left", padx=8)
        tk.Button(cmd_row, text="Send", command=self.send_peer_command, bg='#333333', fg='white').pack(side="left")

        quick = tk.Frame(parent, bg='#1e1e1e')
        quick.pack(fill="x", padx=10, pady=(0, 10))
        for cmd in (
            "peers",
            "files alice",
            "files charlie",
            "swarmdec_rsa test.txt.enc private.pem 8",
        ):
            tk.Button(quick, text=cmd, command=lambda c=cmd: self._quick_cmd(c), bg='#333333', fg='white').pack(side="left", padx=4, pady=2)

    def _build_crypto_tab(self, parent: tk.Frame) -> None:
        self.crypto_in = tk.StringVar(value=str(self.workspace / "test.txt"))
        self.crypto_out = tk.StringVar(value=str(self.workspace / "test.txt.enc"))
        self.crypto_private_key = tk.StringVar(value=str(self.workspace / "private.pem"))
        self.crypto_public_key = tk.StringVar(value=str(self.workspace / "public.pem"))

        frm = tk.Frame(parent, bg='#1e1e1e')
        frm.pack(fill="x", padx=10, pady=10)

        tk.Label(frm, text="Input File", bg='#1e1e1e', fg='white').grid(row=0, column=0, sticky="w", pady=3)
        tk.Entry(frm, textvariable=self.crypto_in, width=70, bg='#1e1e1e', fg='white', insertbackground='white').grid(row=0, column=1, sticky="w", pady=3)
        tk.Button(frm, text="Browse", command=self.pick_crypto_input, bg='#333333', fg='white').grid(row=0, column=2, padx=8)

        tk.Label(frm, text="Output File", bg='#1e1e1e', fg='white').grid(row=1, column=0, sticky="w", pady=3)
        tk.Entry(frm, textvariable=self.crypto_out, width=70, bg='#1e1e1e', fg='white', insertbackground='white').grid(row=1, column=1, sticky="w", pady=3)
        tk.Button(frm, text="Browse", command=self.pick_crypto_output, bg='#333333', fg='white').grid(row=1, column=2, padx=8)

        tk.Label(frm, text="Public Key (RSA)", bg='#1e1e1e', fg='white').grid(row=2, column=0, sticky="w", pady=3)
        tk.Entry(frm, textvariable=self.crypto_public_key, width=70, bg='#1e1e1e', fg='white', insertbackground='white').grid(row=2, column=1, sticky="w", pady=3)
        tk.Button(frm, text="Browse", command=self.pick_public_key, bg='#333333', fg='white').grid(row=2, column=2, padx=8)

        tk.Label(frm, text="Private Key (RSA)", bg='#1e1e1e', fg='white').grid(row=3, column=0, sticky="w", pady=3)
        tk.Entry(frm, textvariable=self.crypto_private_key, width=70, bg='#1e1e1e', fg='white', insertbackground='white').grid(row=3, column=1, sticky="w", pady=3)
        tk.Button(frm, text="Browse", command=self.pick_private_key, bg='#333333', fg='white').grid(row=3, column=2, padx=8)

        btns = tk.Frame(parent, bg='#1e1e1e')
        btns.pack(fill="x", padx=10, pady=8)
        tk.Button(btns, text="Generate RSA Keys", command=self.generate_rsa_keys_action, bg='#333333', fg='white').pack(side="left", padx=8)
        tk.Button(btns, text="Encrypt File (RSA+AES)", command=self.encrypt_file_rsa_action, bg='#333333', fg='white').pack(side="left", padx=8)
        tk.Button(btns, text="Decrypt File (RSA+AES)", command=self.decrypt_file_rsa_action, bg='#333333', fg='white').pack(side="left", padx=8)

    def start_tracker(self) -> None:
        cmd = [
            sys.executable,
            str(self.workspace / "tracker.py"),
            "--host",
            self.tracker_host.get().strip(),
            "--port",
            self.tracker_port.get().strip(),
            "--ttl",
            self.tracker_ttl.get().strip(),
        ]
        self.processes["tracker"] = ManagedProcess("tracker", cmd, self._log)
        self.processes["tracker"].start()

    def stop_tracker(self) -> None:
        proc = self.processes.get("tracker")
        if proc:
            proc.stop()
        else:
            self._log("[tracker] not running")

    def pick_share_file(self) -> None:
        path = filedialog.askopenfilename()
        if path:
            self.peer_share_path.set(path)

    def start_peer(self) -> None:
        name = self.peer_name.get().strip()
        if not name:
            messagebox.showerror("Missing value", "Session Name is required")
            return
        cmd = [
            sys.executable,
            str(self.workspace / "peer.py"),
            "--peer-id",
            self.peer_id.get().strip(),
            "--listen-host",
            self.peer_listen_host.get().strip(),
            "--listen-port",
            self.peer_listen_port.get().strip(),
            "--tracker-host",
            self.peer_tracker_host.get().strip(),
            "--tracker-port",
            self.peer_tracker_port.get().strip(),
        ]
        public_ip = self.peer_public_ip.get().strip()
        if public_ip:
            cmd += ["--public-ip", public_ip]
        share = self.peer_share_path.get().strip()
        if share:
            cmd += ["--share", share]

        self.processes[name] = ManagedProcess(name, cmd, self._log)
        self.processes[name].start()

    def stop_peer(self) -> None:
        name = self.peer_name.get().strip()
        if not name:
            self._log("[peer] enter Session Name to stop")
            return
        proc = self.processes.get(name)
        if proc:
            proc.stop()
        else:
            self._log(f"[{name}] not running")

    def send_peer_command(self) -> None:
        name = self.peer_name.get().strip()
        cmd = self.peer_command.get().strip()
        if not name or not cmd:
            self._log("[peer] Session Name and command required")
            return
        proc = self.processes.get(name)
        if not proc:
            self._log(f"[{name}] not running")
            return
        proc.send(cmd)

    def _quick_cmd(self, cmd: str) -> None:
        self.peer_command.set(cmd)
        self.send_peer_command()

    def pick_crypto_input(self) -> None:
        path = filedialog.askopenfilename()
        if path:
            self.crypto_in.set(path)

    def pick_crypto_output(self) -> None:
        path = filedialog.asksaveasfilename()
        if path:
            self.crypto_out.set(path)

    def pick_public_key(self) -> None:
        path = filedialog.askopenfilename()
        if path:
            self.crypto_public_key.set(path)

    def pick_private_key(self) -> None:
        path = filedialog.askopenfilename()
        if path:
            self.crypto_private_key.set(path)

    def generate_rsa_keys_action(self) -> None:
        try:
            private_path = Path(self.crypto_private_key.get())
            public_path = Path(self.crypto_public_key.get())
            private_path.parent.mkdir(parents=True, exist_ok=True)
            public_path.parent.mkdir(parents=True, exist_ok=True)
            generate_rsa_keypair(private_path, public_path, bits=2048)
            messagebox.showinfo("Success", f"RSA keys generated:\n{private_path}\n{public_path}")
            self._log(f"[crypto] rsa keygen -> {private_path} | {public_path}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("RSA keygen error", str(exc))
            self._log(f"[crypto] rsa keygen error: {exc}")

    def encrypt_file_rsa_action(self) -> None:
        try:
            encrypt_file_hybrid(
                Path(self.crypto_in.get()),
                Path(self.crypto_out.get()),
                Path(self.crypto_public_key.get()),
            )
            messagebox.showinfo("Success", f"Encrypted (RSA+AES):\n{self.crypto_out.get()}")
            self._log(f"[crypto] rsa+aes encrypted -> {self.crypto_out.get()}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Encrypt RSA error", str(exc))
            self._log(f"[crypto] rsa+aes encrypt error: {exc}")

    def decrypt_file_rsa_action(self) -> None:
        try:
            decrypt_file_hybrid(
                Path(self.crypto_in.get()),
                Path(self.crypto_out.get()),
                Path(self.crypto_private_key.get()),
            )
            messagebox.showinfo("Success", f"Decrypted (RSA+AES):\n{self.crypto_out.get()}")
            self._log(f"[crypto] rsa+aes decrypted -> {self.crypto_out.get()}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Decrypt RSA error", str(exc))
            self._log(f"[crypto] rsa+aes decrypt error: {exc}")


def main() -> None:
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
