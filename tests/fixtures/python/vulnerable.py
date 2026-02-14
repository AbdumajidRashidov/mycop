import os
import pickle
import random
import subprocess
import yaml

# SQL Injection - f-string in execute
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    db.execute(query)

# SQL Injection - %-formatting
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id=%s" % user_id)

# OS Command Injection
def ping_host(host):
    os.system("ping -c 1 " + host)

# OS Command Injection - subprocess with shell=True
def run_command(cmd):
    subprocess.call(cmd, shell=True)

# Hardcoded secrets
API_KEY = "sk-1234567890abcdef1234567890abcdef"
password = "SuperSecret123!"

# Insecure random
def generate_token():
    return random.randint(100000, 999999)

# Eval/Exec
def evaluate(expr):
    result = eval(expr)
    return result

def run_code(code):
    exec(code)

# Path traversal
def download_file(filename):
    path = "/uploads/" + filename
    return open(path + ".txt")

# Insecure deserialization
def load_data(data):
    obj = pickle.loads(data)
    return obj

# Insecure YAML loading
def load_config(config_str):
    config = yaml.load(config_str)
    return config

# XSS in template
from markupsafe import Markup
def render_name(name):
    return Markup("<b>" + name + "</b>")

# Log injection
import logging
def log_user_action(request):
    logging.info("User action: " + request.path)
