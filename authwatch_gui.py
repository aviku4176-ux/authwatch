#!/usr/bin/env python3
"""AuthWatch GUI - Tkinter front-end for the authwatch detector.

Usage:  python authwatch_gui.py
"""
from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import authwatch


class AuthWatchGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("AuthWatch - brute-force / credential-stuffing detector")
        self.root.geometry("980x620")
        self.q: queue.Queue = queue.Queue()
        self.worker: threading.Thread | None = None
        self.stop_flag = threading.Event()

        self._build_log_panel()
        self._build_options_panel()
        self._build_results_panel()
        self._build_statusbar()
        self.root.after(100, self._drain_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # -- panels ----------------------------------------------------------

    def _build_log_panel(self):
        frm = ttk.LabelFrame(self.root, text="Log source", padding=8)
        frm.pack(fill="x", padx=8, pady=(8, 4))
        self.logfile = tk.StringVar()
        self.format = tk.StringVar(value="auto")
        ttk.Entry(frm, textvariable=self.logfile, width=70).grid(
            row=0, column=0, padx=(0, 6), sticky="we")
        ttk.Button(frm, text="Browse...", command=self._pick_log).grid(
            row=0, column=1, padx=(0, 4))
        ttk.Label(frm, text="Format:").grid(row=0, column=3)
        ttk.Label(frm, text="Format:").grid(row=0, column=2)
        ttk.Combobox(frm, textvariable=self.format, state="readonly", width=12,
                     values=["auto", "ssh", "pam", "dovecot", "postfix",
                             "http", "json"]).grid(row=0, column=3, padx=6)
        self.tail_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="Tail (live follow)", variable=self.tail_var
                        ).grid(row=0, column=4, padx=6)
        self.cef_var = tk.BooleanVar(value=False)
        self.json_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm, text="CEF", variable=self.cef_var).grid(
            row=0, column=5, padx=2)
        ttk.Checkbutton(frm, text="JSON", variable=self.json_var).grid(
            row=0, column=6, padx=(2, 0))
        frm.columnconfigure(0, weight=1)

    def _pick_log(self):
        path = filedialog.askopenfilename(
            title="Select log file",
            filetypes=[("Log files", "*.log *.txt *.jsonl *.json"),
                       ("All files", "*.*")])
        if path:
            self.logfile.set(path)

    def _load_sample(self):
        sample = os.path.join(os.path.dirname(authwatch.__file__),
                              "examples", "sshd.log")
        if os.path.isfile(sample):
            self.logfile.set(sample)
            self.status.set("Sample loaded: examples/sshd.log  -- click Run detection")
        else:
            self.status.set("Sample not found: " + sample)
    def _build_options_panel(self):
        frm = ttk.LabelFrame(self.root, text="Detection options", padding=8)
        frm.pack(fill="x", padx=8, pady=4)
        self.var = {}
        defaults = {"window": "300", "fail_threshold": "5",
                    "stuff_threshold": "10", "spray_users": "5",
                    "spray_ips": "5", "success_after": "3",
                    "recon_threshold": "30", "user_threshold": "3",
                    "persist_buckets": "6"}
        row = 0
        for i, (key, val) in enumerate(defaults.items()):
            v = tk.StringVar(value=val)
            self.var[key] = v
            col = i % 4
            if i % 4 == 0 and i > 0:
                row += 1
            ttk.Label(frm, text=key.replace("_", " ")).grid(
                row=row, column=col * 2, sticky="e", padx=(8, 2), pady=2)
            ttk.Entry(frm, textvariable=v, width=8).grid(
                row=row, column=col * 2 + 1, sticky="w", pady=2)
        row += 1
        self.allowlist = tk.StringVar(
            value="10.0.0.0/8,192.168.0.0/16,127.0.0.1")
        self.denylist = tk.StringVar(value="")
        self.focus_users = tk.StringVar(value="admin,root")
        self.ban_cmd = tk.StringVar(
            value="iptables -A INPUT -s {ip} -j DROP")
        self.ban_exec = tk.BooleanVar(value=False)
        ttk.Label(frm, text="Allowlist (CIDR/IP)").grid(
            row=row, column=0, sticky="e", padx=(8, 2))
        ttk.Entry(frm, textvariable=self.allowlist, width=30).grid(
            row=row, column=1, columnspan=3, sticky="we", pady=2)
        ttk.Label(frm, text="Denylist").grid(row=row, column=4, sticky="e",
                                             padx=(12, 2))
        ttk.Entry(frm, textvariable=self.denylist, width=20).grid(
            row=row, column=5, sticky="we", pady=2)
        row += 1
        ttk.Label(frm, text="Focus users").grid(row=row, column=0,
                                                sticky="e", padx=(8, 2))
        ttk.Entry(frm, textvariable=self.focus_users, width=30).grid(
            row=row, column=1, columnspan=3, sticky="we", pady=2)
        ttk.Label(frm, text="Ban cmd").grid(row=row, column=4, sticky="e",
                                            padx=(12, 2))
        ttk.Entry(frm, textvariable=self.ban_cmd, width=30).grid(
            row=row, column=5, sticky="we", pady=2)
        row += 1
        row += 1
        self.dry_run = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm, text="Ban dry-run", variable=self.dry_run).grid(
            row=row, column=0, sticky="w", padx=8)

        row += 1
        sep = ttk.Separator(frm, orient="horizontal")
        sep.grid(row=row, column=0, columnspan=6, sticky="we", pady=6)

        row += 1
        ttk.Button(frm, text="Create scheduled task",
                   command=self._create_task).grid(
            row=row, column=0, columnspan=3, sticky="w", padx=8)
        row += 1
        ttk.Button(frm, text="Run detection", command=self._start).grid(
            row=row, column=0, columnspan=6, sticky="e", padx=8, pady=6)
    def _build_results_panel(self):
        frm = ttk.LabelFrame(self.root, text="Alerts", padding=8)
        frm.pack(fill="both", expand=True, padx=8, pady=4)
        cols = ("ts", "severity", "rule", "ip", "user", "count", "detail")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings",
                                 height=14)
        heads = {"ts": "Timestamp", "severity": "Severity", "rule": "Rule",
                 "ip": "IP", "user": "User", "count": "Count",
                 "detail": "Detail"}
        widths = {"ts": 150, "severity": 80, "rule": 180, "ip": 120,
                  "user": 90, "count": 50, "detail": 320}
        for c in cols:
            self.tree.heading(c, text=heads[c])
            self.tree.column(c, width=widths[c], anchor="w")
        sb = ttk.Scrollbar(frm, orient="vertical",
                           command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")
        self.alert_rows = []

    def _build_statusbar(self):
        self.status = tk.StringVar(value="Ready.")
        bar = ttk.Label(self.root, textvariable=self.status, relief="sunken",
                        anchor="w", padding=(6, 2))
        bar.pack(fill="x", side="bottom")

    # -- worker ----------------------------------------------------------

    def _create_task(self):
        path = self.logfile.get().strip()
        if not path or not os.path.isfile(path):
            messagebox.showerror("AuthWatch", "Choose a valid log file first.")
            return
        log_abs = os.path.abspath(path)
        script_abs = os.path.abspath(authwatch.__file__)
        alert_file = os.path.abspath("AuthWatch-alerts.jsonl")
        cmd = f'"{sys.executable}" "{script_abs}" --logfile "{log_abs}" --tail --json --alert-file "{alert_file}"'
        schtasks = f'schtasks /create /tn "AuthWatch" /tr {cmd} /sc minute /mo 10 /f'
        result = os.popen(schtasks).read()
        if "SUCCESS" in result.upper():
            messagebox.showinfo("AuthWatch",
                                f"Task 'AuthWatch' created (every 10 min)\n"
                                f"Alerts -> {alert_file}")
        else:
            messagebox.showerror("AuthWatch", f"Failed:\n{result}")
    def _start(self):
        if self.worker and self.worker.is_alive():
            return
        path = self.logfile.get().strip()
        if not path:
            messagebox.showerror("AuthWatch", "Choose a log file first.")
            return
        if not os.path.isfile(path):
            messagebox.showerror("AuthWatch", "Log file not found:\n" + path)
            return
        for row in self.tree.get_children():
            self.tree.delete(row)
        self.alert_rows = []
        self.stop_flag.clear()
        self.status.set("Running...")
        # Snapshot all tkinter StringVars on the main thread so the worker
        # never touches tk objects.
        opts = {
            "path": path,
            "fmt": self.format.get(),
            "cef": self.cef_var.get(),
            "json": self.json_var.get(),
            "window": float(self.var["window"].get()),
            "fail_threshold": int(self.var["fail_threshold"].get()),
            "stuff_threshold": int(self.var["stuff_threshold"].get()),
            "spray_users": int(self.var["spray_users"].get()),
            "spray_ips": int(self.var["spray_ips"].get()),
            "success_after": int(self.var["success_after"].get()),
            "recon_threshold": int(self.var["recon_threshold"].get()),
            "user_threshold": int(self.var["user_threshold"].get()),
            "persist_buckets": int(self.var["persist_buckets"].get()),
            "allowlist": tuple(authwatch._split_csv(self.allowlist.get())),
            "denylist": tuple(authwatch._split_csv(self.denylist.get())),
            "focus_users": frozenset(
                authwatch._split_csv(self.focus_users.get())),
        }
        self.worker = threading.Thread(target=self._run, args=(opts,),
                                       daemon=True)
        self.worker.start()

    def _run(self, opts: dict):
        try:
            det = authwatch.Detector(
                window=opts["window"],
                fail_threshold=opts["fail_threshold"],
                stuff_threshold=opts["stuff_threshold"],
                spray_users=opts["spray_users"],
                spray_ips=opts["spray_ips"],
                success_after_fails=opts["success_after"],
                recon_threshold=opts["recon_threshold"],
                user_threshold=opts["user_threshold"],
                persist_buckets=opts["persist_buckets"],
                allowlist=opts["allowlist"],
                denylist=opts["denylist"],
                focus_users=opts["focus_users"])
            fmt = opts["fmt"]
            path = opts["path"]
            count = 0
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if self.stop_flag.is_set():
                        break
                    line = line.strip()
                    if not line:
                        continue
                    ev = authwatch.parse_line(line, fmt)
                    if ev is not None:
                        det.feed(ev)
                        count += 1
            self.q.put(("alerts", [authwatch.alert_to_dict(a)
                                   for a in det.alerts]))
            self.q.put(("done", (count, len(det.alerts))))
        except Exception as exc:  # surface worker errors in the UI
            self.q.put(("error", str(exc)))
    # -- queue / UI updates ------------------------------------------------

    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "alerts":
                    for d in payload:
                        self.tree.insert("", "end", values=(
                            d["ts"], d["severity"], d["rule"], d["ip"],
                            d["user"], d["count"], d["detail"]))
                        self.alert_rows.append(d)
                elif kind == "done":
                    events, alerts = payload
                    self.status.set(
                        f"Done: {events} events processed, "
                        f"{alerts} alerts.")
                elif kind == "error":
                    self.status.set("Error.")
                    messagebox.showerror("AuthWatch", payload)
        except queue.Empty:
            pass
        self.root.after(100, self._drain_queue)

    def _on_close(self):
        self.stop_flag.set()
        self.root.destroy()


def main():
    root = tk.Tk()
    AuthWatchGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()