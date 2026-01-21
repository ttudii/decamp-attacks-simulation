# INSTRUCTIONS TO RUN THE GUI
# 
# Ensure you have this exact folder structure:
#       attack_launcher.py (this script)
#       Internal Attacker folder (containing the scripts)
#       External Attacker folder (containing the script)
# 
# Open a terminal in this specific folder.
# Run the command: python attack_launcher.py
# The window will open. When you click the buttons, the scripts located in the sub-folders will be executed.


import tkinter as tk
from tkinter import messagebox
import subprocess
import os
import sys

def execute_script(script_path, script_name):
    if not os.path.exists(script_path):
        messagebox.showerror("Error", f"File not found:\n{script_path}")
        return

    try:
        print(f"--- Initiating: {script_name}")
        messagebox.showinfo("Status", f"executing script: {script_name}")
        
        # execution zone       
        subprocess.Popen(["python", script_path]) 
        
        # Popen is used to run the script in the bckground
        
    except Exception as e:
        messagebox.showerror("Eroare", f"A apărut o eroare la execuție: {e}")

def run_arp_sweep():
    path = os.path.join("Internal Attacker", "arp_sweep_recon.py")
    execute_script(path, "ARP Sweep Recon")

def run_icmp_flood():
    path = os.path.join("Internal Attacker", "icmp_flood_dos.py")
    execute_script(path, "ICMP Flood DoS")

def run_rip_attack():
    path = os.path.join("Internal Attacker", "rip_attack.py")
    execute_script(path, "RIP Attack")

def run_tcp_syn_flood_internal():
    path = os.path.join("Internal Attacker", "tcp_syn_flood_dos.py")
    execute_script(path, "TCP SYN Flood (Internal)")

def run_vpn_scan():
    path = os.path.join("External Attacker", "vpn_tcp_syn_scan_recon.py")
    execute_script(path, "VPN TCP SYN Scan")

# tkinter GUI configuration
root = tk.Tk()
root.title("DeCaMP Simulation Launcher")
root.geometry("400x450")

label_title = tk.Label(root, text="Control panel", font=("Helvetica", 16, "bold"))
label_title.pack(pady=20)

# internal Attacker
frame_internal = tk.LabelFrame(root, text="Internal Attacker", padx=10, pady=10)
frame_internal.pack(fill="x", padx=20, pady=5)

btn_arp = tk.Button(frame_internal, text="ARP Sweep Recon", command=run_arp_sweep, bg="#ffcccb")
btn_arp.pack(fill="x", pady=2)

btn_icmp = tk.Button(frame_internal, text="ICMP Flood DoS", command=run_icmp_flood, bg="#ffcccb")
btn_icmp.pack(fill="x", pady=2)

btn_rip = tk.Button(frame_internal, text="RIP Attack", command=run_rip_attack, bg="#ffcccb")
btn_rip.pack(fill="x", pady=2)

btn_syn_int = tk.Button(frame_internal, text="TCP SYN Flood", command=run_tcp_syn_flood_internal, bg="#ffcccb")
btn_syn_int.pack(fill="x", pady=2)

# external Attacker
frame_external = tk.LabelFrame(root, text="External Attacker", padx=10, pady=10)
frame_external.pack(fill="x", padx=20, pady=15)

btn_vpn = tk.Button(frame_external, text="VPN TCP SYN Scan", command=run_vpn_scan, bg="#lightblue")
btn_vpn.pack(fill="x", pady=2)

btn_exit = tk.Button(root, text="Exit", command=root.quit)
btn_exit.pack(pady=20)

# run main loop of the interface
root.mainloop()