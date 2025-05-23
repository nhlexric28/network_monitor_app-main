from flask import Flask, render_template, request, redirect, session, url_for
import socket, subprocess, json, os

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Load users from JSON
def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except:
        return {}

# Save users to JSON
def save_users(users):
    with open('users.json', 'w') as f:
        json.dump(users, f)

# Get local IP and hostname
def get_local_info():
    hostname = socket.gethostname()
    ip = socket.gethostbyname(hostname)
    return ip, hostname

# Get Wi-Fi SSID (Windows only)
def get_wifi_name():
    try:
        result = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True)
        for line in result.split("\n"):
            if "SSID" in line and "BSSID" not in line:
                return line.split(":")[1].strip()
    except:
        return "Unavailable"

# Scan network for active devices
def scan_network():
    ip_base = get_local_info()[0].rsplit('.', 1)[0]
    # Ping the entire /24 subnet to populate ARP table
    for i in range(1, 255):
        ip = f"{ip_base}.{i}"
        subprocess.Popen(f"ping -n 1 -w 200 {ip}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    import time
    time.sleep(5)

    result = subprocess.check_output("arp -a", shell=True).decode()
    devices = []
    for line in result.splitlines():
        if ip_base in line:
            parts = line.split()
            if len(parts) >= 2:
                devices.append({'ip': parts[0], 'mac': parts[1]})
    return devices

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('dashboard'))
        return "Invalid credentials."
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        if username in users:
            return "User already exists."
        users[username] = password
        save_users(users)
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))

    ip, hostname = get_local_info()
    ssid = get_wifi_name()
    devices = scan_network()

    return render_template('dashboard.html',
                           username=session['username'],
                           ip=ip,
                           hostname=hostname,
                           ssid=ssid,
                           devices=devices)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)