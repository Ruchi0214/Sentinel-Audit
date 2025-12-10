import subprocess
import sys
import time
import os
import re

def kill_process_on_port(port):
    """
    Finds and kills the process listening on the specified port.
    """
    print(f"Checking for process on port {port}...")
    try:
        # Run netstat to find the process
        result = subprocess.run(['netstat', '-ano'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        
        for line in lines:
            if f":{port}" in line and "LISTENING" in line:
                # Extract PID (last element in the line)
                parts = line.split()
                pid = parts[-1]
                
                print(f"Killing process with PID {pid} on port {port}...")
                subprocess.run(['taskkill', '/F', '/PID', pid], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                return
    except Exception as e:
        print(f"Error killing process on port {port}: {e}")

def main():
    print("Initializing System Startup...")
    
    # 1. Kill old processes
    kill_process_on_port(5000)
    kill_process_on_port(8000)
    
    # 2. Start Backend
    print("Starting Backend (Backend.py)...")
    # Using specific python executable from sys.executable to ensure we use the same env
    backend_process = subprocess.Popen([sys.executable, 'Backend.py'], 
                                     creationflags=subprocess.CREATE_NEW_CONSOLE)
    
    # 3. Start Frontend Server
    print("Starting Frontend Server on port 8000...")
    frontend_process = subprocess.Popen([sys.executable, '-m', 'http.server', '8000'],
                                      creationflags=subprocess.CREATE_NEW_CONSOLE)
    
    # 4. Wait
    time.sleep(2)
    
    # 5. Print Success Message (ANSI Green)
    GREEN = '\033[92m'
    RESET = '\033[0m'
    print(f"\n{GREEN}[OK] SYSTEM ONLINE: Open http://localhost:8000{RESET}\n")

if __name__ == "__main__":
    main()
