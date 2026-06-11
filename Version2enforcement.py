#!/usr/bin/env python3
"""
-------------------------------------------------------------------------------
TITLE: Self-Initiating Beacon Enforcer
DESCRIPTION: Fully encapsulated node lifecycle with 5-minute encryption
-------------------------------------------------------------------------------
"""

import os
import sys
import time
import json
import logging
import subprocess
import psutil
from datetime import datetime
from cryptography.fernet import Fernet

# --- CONFIGURATION ---
DENYLIST_FILE    = "process_denylist.json"
ENCRYPTED_FILE   = "process_denylist.enc"
ENFORCE_LOG      = "enforcement.log"
CPU_THRESHOLD    = 0.003   
SCAN_INTERVAL    = 60      
ENFORCE_INTERVAL = 180     
ENCRYPT_INTERVAL = 300     # 5 Minutes
WHITELIST        = ["6.py", "python3", "secure_auto_enforcer.py", "gen_"]

# Generate a static key for this runtime session
KEY              = Fernet.generate_key() 
cipher           = Fernet(KEY)

# --- ENCAPSULATED NODE CONTROLLER ---

class BeaconNode:
    """The master controller that handles self-replication and process life-cycle."""
    def __init__(self):
        self.generation = int(os.environ.get("NODE_GEN", "0"))
        self.max_gen = int(os.environ.get("NODE_MAX", "1"))
        
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [GEN %(gen)s] %(message)s",
            handlers=[logging.FileHandler(ENFORCE_LOG), logging.StreamHandler(sys.stdout)],
        )
        self.log = logging.LoggerAdapter(logging.getLogger("beacon_enforcer"), {'gen': self.generation})
        
        # Initialize components
        self.manager = BlacklistManager(DENYLIST_FILE, ENCRYPTED_FILE, WHITELIST, CPU_THRESHOLD, self.log)
        self.enforcer = ProcessEnforcer(self.log)

    def propagate(self):
        """Self-replication mechanism."""
        if self.generation < self.max_gen:
            try:
                source = open(__file__, "rb").read()
                child_name = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"gen_{self.generation+1}_node.py")
                with open(child_name, "wb") as f_out: f_out.write(source)
                subprocess.Popen([sys.executable, child_name], env={**os.environ, "NODE_GEN": str(self.generation + 1)})
                self.log.info(f"Propagating Beacon Node to Gen {self.generation + 1}...")
            except Exception as e: self.log.error(f"Propagation Error: {e}")

    def run(self):
        """Self-initiating execution loop."""
        self.propagate()
        self.log.info("Beacon Computing Initiative Enforcer operational.")
        
        last_scan = 0
        last_enforce = 0
        last_encrypt = 0
        
        try:
            while True:
                now = time.time()
                if now - last_scan > SCAN_INTERVAL:
                    self.manager.populate()
                    last_scan = now

                if now - last_enforce > ENFORCE_INTERVAL:
                    self.enforcer.enforce(self.manager)
                    last_enforce = now
                
                if now - last_encrypt > ENCRYPT_INTERVAL:
                    self.manager.encrypt_data()
                    last_encrypt = now
                    
                time.sleep(5)
        except KeyboardInterrupt:
            self.log.info("Beacon Enforcer shutting down.")

# --- SUPPORTING CLASSES ---

class BlacklistManager:
    def __init__(self, filepath, enc_path, whitelist, cpu_threshold, log):
        self.filepath = filepath
        self.enc_path = enc_path
        self.whitelist = whitelist
        self.cpu_threshold = cpu_threshold
        self.log = log
        self.data = self._load()

    def _load(self):
        if os.path.exists(self.enc_path):
            try:
                with open(self.enc_path, 'rb') as f:
                    return json.loads(cipher.decrypt(f.read()).decode())
            except Exception as e:
                self.log.error(f"Decryption failed: {e}")
        return {}

    def encrypt_data(self):
        try:
            with open(self.enc_path, 'wb') as f:
                f.write(cipher.encrypt(json.dumps(self.data).encode()))
            self.log.info("Blacklist encrypted.")
        except Exception as e: self.log.error(f"Encryption error: {e}")

    def populate(self):
        # Prime CPU
        for p in psutil.process_iter(['name']):
            try: p.cpu_percent(None)
            except: pass
        time.sleep(1.0)
        
        for p in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cpu = p.cpu_percent(None)
                name = p.info['name'] or ""
                cmdline = " ".join(p.info['cmdline'] or [])
                if any(w in name or w in cmdline for w in self.whitelist): continue
                if cpu > self.cpu_threshold and name not in self.data:
                    self.data[name] = {"first_seen": datetime.now().isoformat(), "peak_cpu": cpu}
            except: continue

    def exists(self, process_name): return process_name in self.data

class ProcessEnforcer:
    def __init__(self, log): self.log = log
    def enforce(self, manager):
        for p in psutil.process_iter(['pid', 'name']):
            try:
                if manager.exists(p.info['name']):
                    p.kill()
                    self.log.warning(f"TERMINATED: {p.info['name']}")
            except: pass

# --- EXECUTION ENTRY POINT ---
if __name__ == "__main__":
    node = BeaconNode()
    node.run()
