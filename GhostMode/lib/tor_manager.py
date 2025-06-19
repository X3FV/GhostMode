import socket
import subprocess

class TorManager:
    def is_running(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect(("127.0.0.1", 9050))
            return True
        except:
            return False
    
    def start(self):
        subprocess.run(["sudo", "service", "tor", "start"])