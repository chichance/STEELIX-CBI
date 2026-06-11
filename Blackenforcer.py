#!/usr/bin/env python3
"""
-------------------------------------------------------------------------------
TITLE: Self-Populating Beacon Enforcer with Scheduled Encryption
DESCRIPTION: Modularized Enforcer with 5-minute Data-at-Rest Encryption
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
# Note: In production, load this from a secure environment variable
KEY              = Fernet.generate_key() 
cipher           = Fernet(KEY)

# Propagation Config
GENERATION  = int(os.environ.get("NODE_GEN", "0"))
MAX_GEN     = int(os.environ.get("NODE_MAX", "1")) 

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [GEN %(gen)s] %(message)s",
    handlers=[logging.FileHandler(ENFORCE_LOG), logging.StreamHandler(sys.stdout)],
)
log = logging.LoggerAdapter(logging.getLogger("beacon_enforcer"), {'gen': GENERATION})

# --- CLASSES ---

class BlacklistManager:
    """Handles the persistence, auto-population, and encryption of the denylist."""
    def __init__(self, filepath, enc_path, whitelist, cpu_threshold):
        self.filepath = filepath
        self.enc_path = enc_path
        self.whitelist = whitelist
        self.cpu_threshold = cpu_threshold
        self.data = self._load()

    def _load(self):
        """Loads data from encrypted file if it exists, otherwise creates empty."""
        if os.path.exists(self.enc_path):
            try:
                with open(self.enc_path, 'rb') as f:
                    encrypted_data = f.read()
                    return json.loads(cipher.decrypt(encrypted_data).decode())
            except Exception as e:
                log.error(f"Decryption failed: {e}")
                return {}
        return {}

    def encrypt_data(self):
        """Encrypts current memory state to disk."""
        try:
            raw_data = json.dumps(self.data).encode()
            with open(self.enc_path, 'wb') as f:
                f.write(cipher.encrypt(raw_data))
            log.info("Blacklist successfully encrypted and saved to disk.")
        except Exception as e:
            log.error(f"Encryption error: {e}")

    def is_protected(self, name, cmdline):
        return any(p in name or p in (cmdline or "") for p in self.whitelist)

    def populate(self):
        """Scans the system and automatically updates the denylist."""
        for p in psutil.process_iter(['name']):
            try: p.cpu_percent(None)
            except: pass
        time.sleep(1.0)
        
        new_entries = 0
        for p in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                cpu = p.cpu_percent(None)
                name = p.info['name'] or ""
                cmdline = " ".join(p.info['cmdline'] or [])
                
                if self.is_protected(name, cmdline): continue

                if cpu > self.cpu_threshold:
                    if name not in self.data:
                        self.data[name] = {
                            "first_seen": datetime.now().isoformat(),
                            "peak_cpu": cpu,
                            "status": "flagged"
                        }
                        new_entries += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
        
        if new_entries > 0:
            log.info(f"Populated {new_entries} new entries to memory.")

    def exists(self, process_name):
        return process_name in self.data

class ProcessEnforcer:
    def __init__(self, action="kill"):
        self.action = action

    def enforce(self, manager):
        for p in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                name = p.info['name'] or ""
                if manager.exists(name):
                    if self.action == "kill":
                        p.kill()
                        log.warning(f"TERMINATED: {name} (Beacon Policy Enforcement)")
            except (psutil.NoSuchProcess, psutil.AccessDenied): pass

# --- OPERATIONAL LOOP ---

if __name__ == "__main__":
    # Propagate logic remains same as previous...
    manager = BlacklistManager(DENYLIST_FILE, ENCRYPTED_FILE, WHITELIST, CPU_THRESHOLD)
    enforcer = ProcessEnforcer()
    
    last_scan = 0
    last_enforce = 0
    last_encrypt = 0
    
    log.info("Beacon Computing Initiative Enforcer operational.")
    try:
        while True:
            now = time.time()
            if now - last_scan > SCAN_INTERVAL:
                manager.populate()
                last_scan = now

            if now - last_enforce > ENFORCE_INTERVAL:
                enforcer.enforce(manager)
                last_enforce = now
            
            # Scheduled Encryption Loop
            if now - last_encrypt > ENCRYPT_INTERVAL:
                manager.encrypt_data()
                last_encrypt = now
                
            time.sleep(5)
    except KeyboardInterrupt:
        log.info("Beacon Enforcer shutting down.")
