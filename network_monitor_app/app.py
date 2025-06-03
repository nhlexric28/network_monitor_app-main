import subprocess
import socket
import threading
import time
import json
from scapy.all import sniff, DNSQR, IP
from flask import Flask, jsonify, render_template, request, redirect, url_for, session

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Blacklisted Domains & IPs
blacklisted_domains = ["shady.ru", "malware.tk", "badhost.cn"]
blacklisted_ips = ["192.168.1.100"]

# Store connected device info
devices_info = {}

# Load users from JSON
def load_users():
    try:
        with open('users.json', 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def save_users(users):
    with open('users.json', 'w') as f:
        json.dump(users, f)

# Scan Devices
def scan_devices():
    global devices_info
    devices_info.clear()
    arp_table = subprocess.check_output("arp -a", shell=True).decode().split("\n")
    for line in arp_table:
        if "dynamic" in line:
            parts = line.split()
            ip = parts[0]
            hostname = get_hostname(ip)
            devices_info[ip] = {
                "hostname": hostname,
                "domains": [],
                "signal": "TBD",
                "flags": {}
            }

# Reverse lookup hostname
def get_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return "Unknown"

# Get WiFi Info
def get_wifi_info():
    try:
        result = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True).split("\n")
        ssid = next((line.split(":")[1].strip() for line in result if "SSID" in line and "BSSID" not in line), "Unknown")
        signal = next((line.split(":")[1].strip() for line in result if "Signal" in line), "N/A")
        return ssid, signal
    except Exception:
        return "Unknown", "N/A"

# Start Monitoring DNS Requests
def dns_sniffer(packet):
    if packet.haslayer(DNSQR) and packet.haslayer(IP):
        ip = packet[IP].src
        domain = packet[DNSQR].qname.decode().strip('.')
        if ip in devices_info:
            devices_info[ip]['domains'].append(domain)
            if domain in blacklisted_domains:
                devices_info[ip]['flags']['domain'] = True

threading.Thread(target=lambda: sniff(filter="udp port 53", prn=dns_sniffer, store=False), daemon=True).start()

# ----------------- Flask Routes -----------------

@app.route('/')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template("dashboard.html", username=session.get('username'), ip=request.remote_addr, hostname=socket.gethostname(), ssid=get_wifi_info()[0], devices=devices_info)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        users = load_users()
        username = request.form['username']
        password = request.form['password']
        if username in users and users[username] == password:
            session['username'] = username
            return redirect(url_for('home'))
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

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    ssid, signal = get_wifi_info()
    return jsonify({"username": session.get('username'), "ip": request.remote_addr, "hostname": socket.gethostname(), "ssid": ssid, "devices": devices_info})

### **Updated JSON Endpoints for Dashboard Interactivity**

@app.route('/blacklist')
def blacklist_view():
    return jsonify({"blacklisted_domains": blacklisted_domains, "blacklisted_ips": blacklisted_ips})


@app.route('/traffic-analysis')
def traffic_analysis():
    return jsonify(devices_info)

@app.route('/threat-detection')
def threat_detection():
    flagged_devices = [ip for ip, device in devices_info.items() if device['flags']]
    return jsonify({"status": "Monitoring active threats", "devices_flagged": len(flagged_devices), "flagged_devices": flagged_devices})

@app.route('/device-management')
def device_management():
    return jsonify(devices_info)

@app.route('/security-tools')
def security_tools():
    return jsonify({"tools": [{"name": "Firewall", "status": "Active"}, {"name": "Intrusion Detection", "status": "Enabled"}]})

@app.route('/logs-reports')
def logs_reports():
    return jsonify({"logs": [{"timestamp": "2025-05-29 14:25:15", "event": "Intrusion detected", "description": "Unauthorized access blocked."},
                             {"timestamp": "2025-05-29 14:27:02", "event": "User login", "description": "Admin logged in."}]})

@app.route('/network-tools')
def network_tools():
    return jsonify({"tools": [{"name": "Ping Test", "status": "Available"}, {"name": "Port Scanner", "status": "Running"}]})

@app.route('/settings')
def settings():
    return jsonify({"Firewall": "Enabled", "Logging": "Active", "Auto-Blocking": "On"})

@app.route('/quick-actions')
def quick_actions():
    return jsonify({"actions": ["Block Suspicious IPs", "Reset Network", "Enable High-Security Mode"]})

@app.route('/help-support')
def help_support():
    return jsonify({"message": "Contact cybersecurity support or browse help documentation."})

if __name__ == '__main__':
    app.run(debug=True)
