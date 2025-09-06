#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Crypto Seed Phrase Generator & Scanner (Tkinter GUI)
----------------------------------------------------
Features:
- Generate 12/24-word BIP39 mnemonics
- Derive Bitcoin P2PKH address from m/44'/0'/0'/0/0 using BIP32 (minimal impl)
- Check balance via Blockstream API
- Multithreaded auto-search & bulk scan
- Thread-safe GUI updates (Tkinter + queues)
- Live matplotlib chart: time vs wallets found
- Save non-zero balance results: found_wallets/*.txt and found_wallets.csv
- Export ZIP of found wallets
- Optional Telegram alerts (set env vars or edit config in code)

Author: ChatGPT
License: MIT
"""
import os
import sys
import time
import csv
import math
import json
import hmac
import queue
import base64
import random
import string
import hashlib
import threading
import requests
import datetime
import traceback
from dataclasses import dataclass, field
from typing import Optional, Tuple, List

# GUI
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

# Plotting
import matplotlib
matplotlib.use("TkAgg")  # ensure Tk backend
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# Crypto deps
from mnemonic import Mnemonic
from ecdsa import SigningKey, SECP256k1
import base58

APP_NAME = "Crypto Seed Phrase Generator & Scanner"
FOUND_DIR = "found_wallets"
FOUND_CSV = os.path.join(FOUND_DIR, "found_wallets.csv")
DEFAULT_API = "https://blockstream.info/api"
USER_AGENT = f"{APP_NAME}/1.0"

# ----------- Utility: BIP32 minimal implementation -----------
# Based on BIP32 spec, minimal subset to derive m/44'/0'/0'/0/0 from seed bytes
BIP32_HARDEN = 0x80000000
CURVE_ORDER = SECP256k1.generator.order()

def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()

def ser32(i: int) -> bytes:
    return i.to_bytes(4, "big")

def ser256(p: int) -> bytes:
    return p.to_bytes(32, "big")

def parse256(b: bytes) -> int:
    return int.from_bytes(b, "big")

def point_pubkey_compressed(privkey_int: int) -> bytes:
    sk = SigningKey.from_secret_exponent(privkey_int % CURVE_ORDER, curve=SECP256k1, hashfunc=hashlib.sha256)
    vk = sk.get_verifying_key()
    # Compressed: 02 if y is even else 03, followed by x coord
    px = vk.pubkey.point.x()
    py = vk.pubkey.point.y()
    prefix = b'\x02' if (py % 2 == 0) else b'\x03'
    return prefix + px.to_bytes(32, "big")

def hash160(b: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

def base58check_encode(prefix: bytes, payload: bytes) -> str:
    data = prefix + payload
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return base58.b58encode(data + checksum).decode()

def ckd_priv(parent_k: int, parent_c: bytes, index: int) -> Tuple[int, bytes]:
    if index & BIP32_HARDEN:
        data = b"\x00" + ser256(parent_k) + ser32(index)
    else:
        data = point_pubkey_compressed(parent_k) + ser32(index)
    I = hmac_sha512(parent_c, data)
    Il, Ir = I[:32], I[32:]
    child_k = (parse256(Il) + parent_k) % CURVE_ORDER
    if child_k == 0:
        raise ValueError("Derived invalid child key")
    return child_k, Ir

def master_key_from_seed(seed: bytes) -> Tuple[int, bytes]:
    I = hmac_sha512(b"Bitcoin seed", seed)
    Il, Ir = I[:32], I[32:]
    k = parse256(Il) % CURVE_ORDER
    if k == 0:
        raise ValueError("Invalid master key")
    return k, Ir

def derive_priv_from_path(seed: bytes, path: str) -> int:
    k, c = master_key_from_seed(seed)
    if path.startswith("m/"):
        components = path.lstrip("m/").split("/")
    else:
        components = path.split("/")
    for comp in components:
        hardened = comp.endswith("'")
        index = int(comp[:-1]) if hardened else int(comp)
        if hardened:
            index |= BIP32_HARDEN
        k, c = ckd_priv(k, c, index)
    return k

def p2pkh_address_from_privkey_int(privkey_int: int, mainnet: bool = True) -> str:
    pubkey = point_pubkey_compressed(privkey_int)
    h160 = hash160(pubkey)
    prefix = b"\x00" if mainnet else b"\x6f"
    return base58check_encode(prefix, h160)

def mnemonic_to_address(mnemonic: str, passphrase: str = "") -> Tuple[str, str]:
    """Return (address, derivation_path) using m/44'/0'/0'/0/0"""
    mobj = Mnemonic("english")
    if not mobj.check(mnemonic):
        # Allow scanning "random words" by hashing when invalid, but mark as non-standard
        seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"nonstandard", 2048, dklen=64)
        path = "nonstandard/sha512->priv->addr"
    else:
        seed = mobj.to_seed(mnemonic, passphrase=passphrase)
        path = "m/44'/0'/0'/0/0"
    priv = derive_priv_from_path(seed, "44'/0'/0'/0/0" if path.startswith("m/") else "")
    addr = p2pkh_address_from_privkey_int(priv, mainnet=True)
    return addr, path

# ----------- Balance check -----------
def get_btc_balance_sats(address: str, api_base: str = DEFAULT_API, timeout: float = 10.0) -> Optional[int]:
    try:
        url = f"{api_base}/address/{address}"
        headers = {"User-Agent": USER_AGENT}
        r = requests.get(url, headers=headers, timeout=timeout)
        if r.status_code != 200:
            return None
        data = r.json()
        # Use chain_stats (confirmed) + mempool_stats (unconfirmed); here confirmed only
        funded = data.get("chain_stats", {}).get("funded_txo_sum", 0)
        spent = data.get("chain_stats", {}).get("spent_txo_sum", 0)
        mem_funded = data.get("mempool_stats", {}).get("funded_txo_sum", 0)
        mem_spent = data.get("mempool_stats", {}).get("spent_txo_sum", 0)
        balance = (funded - spent) + (mem_funded - mem_spent)
        return int(balance)
    except Exception:
        return None

def sats_to_btc(sats: int) -> float:
    return sats / 1e8

# ----------- Persistence -----------
def ensure_found_dirs():
    os.makedirs(FOUND_DIR, exist_ok=True)
    if not os.path.exists(FOUND_CSV):
        with open(FOUND_CSV, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "mnemonic", "address", "balance_sats", "balance_btc", "derivation_path"])

def save_found_wallet(mnemonic: str, address: str, balance_sats: int, derivation_path: str):
    ensure_found_dirs()
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    # individual txt
    safe_addr = address
    txt_path = os.path.join(FOUND_DIR, f"{safe_addr}.txt")
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"timestamp: {ts}\nmnemonic: {mnemonic}\naddress: {address}\nbalance_sats: {balance_sats}\n"
                f"balance_btc: {sats_to_btc(balance_sats):.8f}\nderivation_path: {derivation_path}\n")
    # csv append
    with open(FOUND_CSV, "a", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow([ts, mnemonic, address, balance_sats, f"{sats_to_btc(balance_sats):.8f}", derivation_path])

# ----------- Telegram (optional) -----------
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

def telegram_notify(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        requests.post(url, data={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=10)
    except Exception:
        pass

# ----------- Worker logic -----------
@dataclass
class ScanResult:
    mnemonic: str
    address: str
    balance_sats: Optional[int]
    derivation_path: str
    error: Optional[str] = None

# ----------- GUI App -----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1100x750")
        self.configure(bg="#111111")
        self.style = ttk.Style(self)
        # theme colors
        self.bg = "#111111"
        self.fg = "#f5f5f5"
        self.card = "#1b1b1b"
        self.accent = "#3b82f6"
        self.warn = "#ef4444"
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        self.style.configure("TLabel", background=self.bg, foreground=self.fg)
        self.style.configure("TCheckbutton", background=self.bg, foreground=self.fg)
        self.style.configure("TButton", font=("Segoe UI", 10, "bold"))
        self.style.configure("Card.TFrame", background=self.card)
        self.style.configure("Accent.TButton", relief="flat")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        # State
        self.stop_event = threading.Event()
        self.executor: Optional[threading.Thread] = None
        self.pool: Optional[concurrent.futures.ThreadPoolExecutor] = None
        self.event_q: "queue.Queue[ScanResult]" = queue.Queue()
        self.mnemo = Mnemonic("english")
        self.stats_lock = threading.Lock()
        self.start_time = time.time()
        self.total_checked = 0
        self.wallets_found = 0
        self.bulk_total = 0
        self.bulk_done = 0

        # Build UI
        self._build_ui()
        self._build_chart()

        # Poll queues / refresh UI
        self.after(100, self._process_queue)
        self.after(500, self._refresh_stats)
        self.after(1000, self._update_chart_timer)

    def _build_ui(self):
        # Top controls
        top = ttk.Frame(self, style="Card.TFrame", padding=10)
        top.pack(fill="x", padx=10, pady=10)

        # Word count
        ttk.Label(top, text="Words:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.word_var = tk.StringVar(value="12")
        word_menu = ttk.Combobox(top, textvariable=self.word_var, values=["12", "24"], width=6, state="readonly")
        word_menu.grid(row=0, column=1, padx=5, pady=5)

        # Only save >0
        self.only_nonzero = tk.BooleanVar(value=True)
        chk = ttk.Checkbutton(top, text="Only save wallets with balance > 0", variable=self.only_nonzero)
        chk.grid(row=0, column=2, padx=10, pady=5)

        # Threads
        cores = max(1, os.cpu_count() or 1)
        default_threads = max(1, int(cores * 0.5))
        ttk.Label(top, text=f"Threads (cores={cores}):").grid(row=0, column=3, sticky="e", padx=5, pady=5)
        self.thread_var = tk.IntVar(value=default_threads)
        self.thread_spin = ttk.Spinbox(top, from_=1, to=max(1, cores*4), textvariable=self.thread_var, width=6)
        self.thread_spin.grid(row=0, column=4, padx=5, pady=5)

        self.thread_warn = ttk.Label(top, text="", foreground=self.warn)
        self.thread_warn.grid(row=0, column=5, sticky="w", padx=10)

        # Buttons
        btns = ttk.Frame(self, style="Card.TFrame", padding=10)
        btns.pack(fill="x", padx=10)

        self.btn_generate_one = ttk.Button(btns, text="Generate One", command=self.on_generate_one)
        self.btn_generate_one.grid(row=0, column=0, padx=5, pady=5)

        self.btn_start = ttk.Button(btns, text="Start Auto Search", command=self.on_start)
        self.btn_start.grid(row=0, column=1, padx=5, pady=5)

        self.btn_stop = ttk.Button(btns, text="Stop", command=self.on_stop, state="disabled")
        self.btn_stop.grid(row=0, column=2, padx=5, pady=5)

        self.btn_bulk = ttk.Button(btns, text="Bulk Scan From File", command=self.on_bulk)
        self.btn_bulk.grid(row=0, column=3, padx=5, pady=5)

        self.btn_export_zip = ttk.Button(btns, text="Export Found as .zip", command=self.on_export_zip)
        self.btn_export_zip.grid(row=0, column=4, padx=5, pady=5)

        # Output
        out = ttk.Frame(self, style="Card.TFrame", padding=10)
        out.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(out, text="Output:").pack(anchor="w")
        self.output = tk.Text(out, height=10, bg="#0f0f0f", fg=self.fg, insertbackground=self.fg, wrap="word")
        self.output.pack(fill="both", expand=True)

        # Stats
        stats = ttk.Frame(self, style="Card.TFrame", padding=10)
        stats.pack(fill="x", padx=10, pady=10)

        self.uptime_var = tk.StringVar(value="00:00:00")
        self.total_var = tk.StringVar(value="0")
        self.found_var = tk.StringVar(value="0")

        ttk.Label(stats, text="Uptime:").grid(row=0, column=0, sticky="e", padx=5)
        ttk.Label(stats, textvariable=self.uptime_var).grid(row=0, column=1, sticky="w", padx=5)

        ttk.Label(stats, text="Total seeds checked:").grid(row=0, column=2, sticky="e", padx=5)
        ttk.Label(stats, textvariable=self.total_var).grid(row=0, column=3, sticky="w", padx=5)

        ttk.Label(stats, text="Wallets found:").grid(row=0, column=4, sticky="e", padx=5)
        ttk.Label(stats, textvariable=self.found_var).grid(row=0, column=5, sticky="w", padx=5)

        # Progress
        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0,10))

    def _build_chart(self):
        chart_frame = ttk.Frame(self, style="Card.TFrame", padding=10)
        chart_frame.pack(fill="both", expand=False, padx=10, pady=(0,10))

        self.fig = Figure(figsize=(6,2.8), dpi=100)
        self.ax = self.fig.add_subplot(111)
        self.ax.set_xlabel("Time (s)")
        self.ax.set_ylabel("Wallets found")
        self.ax.grid(True, alpha=0.3)
        self.line, = self.ax.plot([], [], linewidth=2)
        self.times: List[float] = []
        self.counts: List[int] = []

        self.canvas = FigureCanvasTkAgg(self.fig, master=chart_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    # ------------- Event handlers -------------
    def on_generate_one(self):
        try:
            words = int(self.word_var.get())
            mnemonic = self.mnemo.generate(strength=128 if words == 12 else 256)
            self._scan_one_mnemonic(mnemonic)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _scan_one_mnemonic(self, mnemonic: str):
        def task():
            try:
                address, path = mnemonic_to_address(mnemonic)
                bal = get_btc_balance_sats(address)
                self.event_q.put(ScanResult(mnemonic, address, bal, path))
            except Exception as e:
                self.event_q.put(ScanResult(mnemonic, "", None, "", error=str(e)))
        threading.Thread(target=task, daemon=True).start()

    def on_start(self):
        try:
            import concurrent.futures
            self.thread_warn.configure(text="")
            cores = max(1, os.cpu_count() or 1)
            threads = int(self.thread_var.get())
            if threads > cores * 2:
                self.thread_warn.configure(text=f"Warning: {threads} threads may overload CPU (cores={cores}).")

            self.stop_event.clear()
            self.btn_start.configure(state="disabled")
            self.btn_stop.configure(state="normal")

            self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
            for _ in range(threads):
                self.pool.submit(self._auto_worker)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start: {e}")

    def _auto_worker(self):
        throttle = 0.05
        words = int(self.word_var.get())
        while not self.stop_event.is_set():
            try:
                mnemonic = self.mnemo.generate(strength=128 if words == 12 else 256)
                address, path = mnemonic_to_address(mnemonic)
                bal = get_btc_balance_sats(address)
                self.event_q.put(ScanResult(mnemonic, address, bal, path))
                time.sleep(throttle)
            except Exception as e:
                self.event_q.put(ScanResult("?", "", None, "", error=str(e)))
                time.sleep(0.1)

    def on_stop(self):
        self.stop_event.set()
        if self.pool:
            self.pool.shutdown(wait=False, cancel_futures=True)
            self.pool = None
        self.btn_start.configure(state="normal")
        self.btn_stop.configure(state="disabled")

    def on_bulk(self):
        path = filedialog.askopenfilename(title="Select .txt with seed phrases (one per line)",
                                          filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                seeds = [line.strip() for line in f if line.strip()]
            self.bulk_total = len(seeds)
            self.bulk_done = 0
            self.progress.configure(mode="determinate", maximum=self.bulk_total, value=0)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read file: {e}")
            return

        def worker(m):
            try:
                address, dpath = mnemonic_to_address(m)
                bal = get_btc_balance_sats(address)
                self.event_q.put(ScanResult(m, address, bal, dpath))
            except Exception as e:
                self.event_q.put(ScanResult(m, "", None, "", error=str(e)))

        import concurrent.futures
        self.stop_event.clear()
        threads = max(1, min(int(self.thread_var.get()), 64))
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for m in seeds:
                if self.stop_event.is_set():
                    break
                ex.submit(worker, m)

    def on_export_zip(self):
        ensure_found_dirs()
        ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
        zipname = filedialog.asksaveasfilename(title="Save ZIP", defaultextension=".zip",
                                               initialfile=f"found_wallets_{ts}.zip",
                                               filetypes=[("ZIP archive","*.zip")])
        if not zipname:
            return
        try:
            with zipfile.ZipFile(zipname, "w", compression=zipfile.ZIP_DEFLATED) as z:
                for root, _, files in os.walk(FOUND_DIR):
                    for fn in files:
                        fp = os.path.join(root, fn)
                        z.write(fp, arcname=os.path.relpath(fp, FOUND_DIR))
            messagebox.showinfo("Export", f"Saved ZIP: {zipname}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create ZIP: {e}")

    # ------------- UI update loops -------------
    def _process_queue(self):
        try:
            while True:
                item: ScanResult = self.event_q.get_nowait()
                self._handle_scan_result(item)
        except queue.Empty:
            pass
        self.after(100, self._process_queue)

    def _handle_scan_result(self, res: ScanResult):
        with self.stats_lock:
            self.total_checked += 1
            if self.bulk_total > 0:
                self.bulk_done += 1
                self.progress.configure(value=self.bulk_done)
                if self.bulk_done >= self.bulk_total:
                    # reset after short delay
                    self.after(1500, lambda: (self._reset_bulk_progress()))

        if res.error:
            self._append_output(f"[ERROR] {res.error}\n")
            return

        bal_str = "N/A" if res.balance_sats is None else f"{res.balance_sats} sats ({sats_to_btc(res.balance_sats):.8f} BTC)"
        self._append_output(f"Seed: {res.mnemonic}\nAddr: {res.address}\nBal : {bal_str}\n----\n")

        if res.balance_sats is not None:
            should_save = (res.balance_sats > 0) if self.only_nonzero.get() else True
            if should_save:
                save_found_wallet(res.mnemonic, res.address, res.balance_sats, res.derivation_path)
                with self.stats_lock:
                    self.wallets_found += 1
                telegram_notify(f"FOUND: {res.address} has {res.balance_sats} sats ({sats_to_btc(res.balance_sats):.8f} BTC)")

    def _reset_bulk_progress(self):
        self.bulk_total = 0
        self.bulk_done = 0
        self.progress.configure(value=0, maximum=100)

    def _append_output(self, text: str):
        self.output.insert("end", text)
        self.output.see("end")

    def _refresh_stats(self):
        elapsed = int(time.time() - self.start_time)
        h = elapsed // 3600
        m = (elapsed % 3600) // 60
        s = elapsed % 60
        self.uptime_var.set(f"{h:02d}:{m:02d}:{s:02d}")
        with self.stats_lock:
            self.total_var.set(str(self.total_checked))
            self.found_var.set(str(self.wallets_found))

        # thread warning update
        try:
            cores = max(1, os.cpu_count() or 1)
            threads = int(self.thread_var.get())
            if threads > cores * 2:
                self.thread_warn.configure(text=f"High thread count ({threads}) may cause lag")
            elif threads > cores:
                self.thread_warn.configure(text=f"Above core count ({threads}>{cores})")
            else:
                self.thread_warn.configure(text="")
        except Exception:
            pass

        self.after(500, self._refresh_stats)

    def _update_chart_timer(self):
        t = time.time() - self.start_time
        with self.stats_lock:
            count = self.wallets_found
        self.times.append(t)
        self.counts.append(count)
        # keep last 600 points
        if len(self.times) > 600:
            self.times = self.times[-600:]
            self.counts = self.counts[-600:]
        self.line.set_data(self.times, self.counts)
        if self.times:
            self.ax.set_xlim(self.times[0], self.times[-1] + 1)
            self.ax.set_ylim(0, max(1, max(self.counts)))
        self.canvas.draw_idle()
        self.after(1000, self._update_chart_timer)

    def on_close(self):
        self.on_stop()
        self.destroy()

# ---- main ----
if __name__ == "__main__":
    # Ensure save dir exists
    ensure_found_dirs()
    # Start app
    app = App()
    app.mainloop()
