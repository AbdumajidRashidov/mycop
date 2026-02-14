import secrets
import subprocess

# Safe SQL - parameterized query
def login(username, password):
    cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))

# Safe subprocess - no shell
def run_command(args):
    subprocess.run(["ping", "-c", "1", args], shell=False)

# Safe random
def generate_token():
    return secrets.token_hex(32)

# Safe file access with validation
def download_file(filename):
    import os
    safe_path = os.path.join("/uploads", os.path.basename(filename))
    if not safe_path.startswith("/uploads"):
        raise ValueError("Invalid path")
    return open(safe_path)
