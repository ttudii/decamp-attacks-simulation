import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import subprocess
import os
import sys
import signal

INTERNAL_DIR = "Internal Attacker"
EXTERNAL_DIR = "External Attacker"

ATTACKS = [
    ("ARP Sweep Recon",       os.path.join(INTERNAL_DIR, "arp_sweep_recon.py")),
    ("ICMP Flood DoS",        os.path.join(INTERNAL_DIR, "icmp_flood_dos.py")),
    ("RIP Attack",            os.path.join(INTERNAL_DIR, "rip_attack.py")),
    ("TCP SYN Flood (Int)",   os.path.join(INTERNAL_DIR, "tcp_syn_flood_dos.py")),
    ("TCP SYN Scan",      os.path.join(EXTERNAL_DIR, "vpn_tcp_syn_scan_recon.py")),
]

class AttackLauncher(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("DeCaMP Simulation Launcher")
        self.geometry("450x550")
        self.minsize(400, 500)
        
        # state tracking
        self.current_proc = None
        self.current_name = None

        self.style = ttk.Style()
        try:
            self.style.theme_use('clam')
        except tk.TclError:
            pass

        self._build_ui()

    def _build_ui(self):
        main_frame = ttk.Frame(self, padding="10 10 10 0")
        main_frame.pack(fill="both", expand=True)

        # header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill="x", pady=(0, 15))
        
        lbl_title = ttk.Label(header_frame, text="Attack Simulation Controller", font=("Segoe UI", 12, "bold"))
        lbl_title.pack(anchor="w")
        
        lbl_desc = ttk.Label(header_frame, text="Select an attack below to execute the script in a new terminal.")
        lbl_desc.pack(anchor="w")

        # attack vector groups
        # we separate attacks into Internal and External groups
        
        # 1. internal attacks group
        self.grp_internal = ttk.LabelFrame(main_frame, text="Internal Vectors", padding="10 5")
        self.grp_internal.pack(fill="x", pady=(0, 10))

        # 2. external attacks group
        self.grp_external = ttk.LabelFrame(main_frame, text="External Vectors", padding="10 5")
        self.grp_external.pack(fill="x", pady=(0, 10))

        # populate buttons
        for name, path in ATTACKS:
            if path.startswith(INTERNAL_DIR):
                self._create_btn(self.grp_internal, name, path)
            else:
                self._create_btn(self.grp_external, name, path)

        # footer controls (stop/exit)
        footer_frame = ttk.Frame(main_frame)
        footer_frame.pack(fill="x", pady=(20, 0), side="bottom")

        self.btn_stop = ttk.Button(
            footer_frame, 
            text="Stop Active Attack", 
            command=self.stop_attack,
            state="disabled"
        )
        self.btn_stop.pack(side="left")

        btn_exit = ttk.Button(footer_frame, text="Exit", command=self.safe_exit)
        btn_exit.pack(side="right")

        # status bar
        self.status_var = tk.StringVar(value="Ready")
        self.statusbar = ttk.Label(
            self, 
            textvariable=self.status_var, 
            relief=tk.SUNKEN, 
            anchor="w", 
            padding=(5, 2)
        )
        self.statusbar.pack(side="bottom", fill="x")

    def _create_btn(self, parent, name, path):
        """Helper to create standard width buttons"""
        btn = ttk.Button(
            parent,
            text=name,
            command=lambda: self.run_attack(name, path)
        )

        btn.pack(fill="x", pady=2)

    def run_attack(self, script_name, script_path):
        if not os.path.exists(script_path):
            messagebox.showerror("Error", f"Script not found:\n{script_path}")
            return

        if self.current_proc and self.current_proc.poll() is None:
            if not messagebox.askyesno("Confirm", f"'{self.current_name}' is currently running.\n\nStop it and start '{script_name}'?"):
                return
            self.stop_attack()

        try:
            py = sys.executable
            proc = subprocess.Popen(
                [
                    "x-terminal-emulator", "-e",
                    "bash", "-lc",
                    f'"{py}" "{script_path}"; exec bash'
                ],
                start_new_session=True
            )

            self.current_proc = proc
            self.current_name = script_name
            self.status_var.set(f"Running: {script_name}")
            self.btn_stop.config(state="normal")

        except Exception as e:
            messagebox.showerror("Execution Error", str(e))
            self.status_var.set("Error during execution")
            self.btn_stop.config(state="disabled")

    def stop_attack(self):
        if not self.current_proc or self.current_proc.poll() is not None:
            self.status_var.set("No active process to stop.")
            self.btn_stop.config(state="disabled")
            return

        try:
            os.killpg(self.current_proc.pid, signal.SIGTERM)
        except Exception:
            try:
                self.current_proc.terminate()
            except Exception:
                pass

        self.status_var.set(f"Terminated: {self.current_name}")
        self.btn_stop.config(state="disabled")
        self.current_proc = None
        self.current_name = None

    def safe_exit(self):
        if self.current_proc and self.current_proc.poll() is None:
            if messagebox.askyesno("Exit", "An attack is still running.\nStop it and exit?"):
                self.stop_attack()
            else:
                return
        self.destroy()

if __name__ == "__main__":
    app = AttackLauncher()
    app.mainloop()