import streamlit as st
import pandas as pd
import random
import time
import hashlib
import json
import os
from datetime import datetime


USERS_FILE = "streamlit_users.json"


st.set_page_config(
    page_title="Intrusion Detection System",
    page_icon="🛡️",
    layout="wide"
)


st.markdown(
    """
    <style>
    .main-title {
        font-size: 44px;
        font-weight: 800;
        color: #0F172A;
        margin-bottom: 4px;
    }
    .subtitle {
        color: #64748B;
        font-size: 17px;
        margin-bottom: 22px;
    }
    .hero {
        background: linear-gradient(135deg, #0F172A 0%, #1D4ED8 100%);
        color: white;
        padding: 25px;
        border-radius: 18px;
        margin-bottom: 20px;
    }
    .hero h3 {
        margin: 0 0 8px 0;
        font-size: 25px;
    }
    .hero p {
        color: #DBEAFE;
        font-size: 15px;
        margin: 0;
    }
    .alert-box {
        background-color: #FEF2F2;
        border: 1px solid #FCA5A5;
        color: #991B1B;
        padding: 16px;
        border-radius: 12px;
        font-weight: 700;
        margin-bottom: 12px;
    }
    .success-box {
        background-color: #ECFDF5;
        border: 1px solid #A7F3D0;
        color: #065F46;
        padding: 14px;
        border-radius: 12px;
        font-weight: 600;
        margin-bottom: 12px;
    }
    .terminal {
        background-color: #0B1120;
        color: #E5E7EB;
        padding: 18px;
        border-radius: 14px;
        font-family: Consolas, monospace;
        height: 360px;
        overflow-y: auto;
        white-space: pre-wrap;
        border: 1px solid #1E293B;
    }
    </style>
    """,
    unsafe_allow_html=True
)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def load_users():
    if not os.path.exists(USERS_FILE):
        return []
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except Exception:
        return []


def save_users(users):
    with open(USERS_FILE, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)


def create_account(full_name, username, email, password, confirm_password):
    if not full_name or not username or not email or not password or not confirm_password:
        st.error("Please fill in all fields.")
        return

    if password != confirm_password:
        st.error("Passwords do not match.")
        return

    users = load_users()

    for user in users:
        if user["username"].lower() == username.lower() or user["email"].lower() == email.lower():
            st.error("Username or email already exists.")
            return

    users.append({
        "full_name": full_name,
        "username": username,
        "email": email,
        "password": hash_password(password)
    })

    save_users(users)
    st.success("Account created successfully. You can now login.")


def login_user(username_or_email, password):
    users = load_users()
    hashed = hash_password(password)

    for user in users:
        if (
            user["username"].lower() == username_or_email.lower()
            or user["email"].lower() == username_or_email.lower()
        ) and user["password"] == hashed:
            st.session_state.logged_in = True
            st.session_state.current_user = user
            st.rerun()

    st.error("Invalid username/email or password.")


def init_state():
    defaults = {
        "logged_in": False,
        "current_user": None,
        "ids_running": False,
        "packets": [],
        "alerts": [],
        "output": [],
        "protocol_stats": {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0},
        "attack_stats": {"Port Scan": 0, "SYN Flood": 0, "ICMP Flood": 0},
        "suspicious_ips": set(),
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def random_ip(private=True):
    if private:
        return f"192.168.{random.randint(0, 255)}.{random.randint(2, 254)}"

    return f"{random.randint(8, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def random_packet():
    protocol = random.choices(
        ["TCP", "UDP", "ICMP", "OTHER"],
        weights=[55, 25, 15, 5],
        k=1
    )[0]

    src_ip = random_ip(private=True)
    dst_ip = random_ip(private=False)

    src_port = ""
    dst_port = ""
    flags = ""

    if protocol == "TCP":
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 53, 22, 21, 25, 110, 143, 8080])
        flags = random.choice(["S", "A", "PA", "FA"])

    elif protocol == "UDP":
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([53, 67, 68, 123, 500, 1900])
        flags = ""

    elif protocol == "ICMP":
        src_port = ""
        dst_port = ""
        flags = ""

    packet_length = random.randint(60, 1500)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return {
        "timestamp": timestamp,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "flags": flags,
        "packet_length": packet_length
    }


def add_output(message):
    st.session_state.output.append(message)
    st.session_state.output = st.session_state.output[-200:]


def add_packet(packet):
    st.session_state.packets.append(packet)
    st.session_state.packets = st.session_state.packets[-500:]

    protocol = packet["protocol"]
    if protocol in st.session_state.protocol_stats:
        st.session_state.protocol_stats[protocol] += 1
    else:
        st.session_state.protocol_stats["OTHER"] += 1

    if protocol == "TCP":
        add_output(
            f"[TCP] {packet['src_ip']}:{packet['src_port']} -> "
            f"{packet['dst_ip']}:{packet['dst_port']} | Flags={packet['flags']}"
        )
    elif protocol == "UDP":
        add_output(
            f"[UDP] {packet['src_ip']}:{packet['src_port']} -> "
            f"{packet['dst_ip']}:{packet['dst_port']}"
        )
    elif protocol == "ICMP":
        add_output(f"[ICMP] {packet['src_ip']} -> {packet['dst_ip']}")
    else:
        add_output(f"[OTHER] {packet['src_ip']} -> {packet['dst_ip']}")


def generate_live_traffic():
    if st.session_state.ids_running:
        for _ in range(random.randint(3, 8)):
            add_packet(random_packet())


def simulate_port_scan():
    attacker_ip = random_ip(private=True)
    target_ip = random_ip(private=True)
    ports = random.sample(range(20, 1000), 12)

    add_output("")
    add_output("Simulating Port Scan attack...")

    for port in ports:
        packet = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "protocol": "TCP",
            "src_port": random.randint(1024, 65535),
            "dst_port": port,
            "flags": "S",
            "packet_length": random.randint(60, 120)
        }
        add_packet(packet)

    msg = f"[ALERT] Possible Port Scan detected from suspicious IP: {attacker_ip}"
    st.session_state.alerts.append(msg)
    st.session_state.suspicious_ips.add(attacker_ip)
    st.session_state.attack_stats["Port Scan"] += 1
    add_output(msg)
    add_output("-" * 70)


def simulate_syn_flood():
    attacker_ip = random_ip(private=True)
    target_ip = random_ip(private=True)
    target_port = random.choice([80, 443, 8080])

    add_output("")
    add_output("Simulating SYN Flood attack...")

    for _ in range(25):
        packet = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "protocol": "TCP",
            "src_port": random.randint(1024, 65535),
            "dst_port": target_port,
            "flags": "S",
            "packet_length": random.randint(60, 120)
        }
        add_packet(packet)

    msg = f"[ALERT] Possible SYN Flood detected from suspicious IP: {attacker_ip}"
    st.session_state.alerts.append(msg)
    st.session_state.suspicious_ips.add(attacker_ip)
    st.session_state.attack_stats["SYN Flood"] += 1
    add_output(msg)
    add_output("-" * 70)


def simulate_icmp_flood():
    attacker_ip = random_ip(private=True)
    target_ip = random_ip(private=True)

    add_output("")
    add_output("Simulating ICMP Flood attack...")

    for _ in range(25):
        packet = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "src_ip": attacker_ip,
            "dst_ip": target_ip,
            "protocol": "ICMP",
            "src_port": "",
            "dst_port": "",
            "flags": "",
            "packet_length": random.randint(60, 120)
        }
        add_packet(packet)

    msg = f"[ALERT] Possible ICMP Flood detected from suspicious IP: {attacker_ip}"
    st.session_state.alerts.append(msg)
    st.session_state.suspicious_ips.add(attacker_ip)
    st.session_state.attack_stats["ICMP Flood"] += 1
    add_output(msg)
    add_output("-" * 70)


def login_page():
    st.markdown(
        """
        <div style="text-align:center; padding:30px 0;">
            <h1 style="font-size:50px; color:#0F172A;">Intrusion Detection System</h1>
            <p style="font-size:18px; color:#64748B;">Cyber Security Web Dashboard</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    tab1, tab2 = st.tabs(["Login", "Create Account"])

    with tab1:
        st.subheader("Login")
        username_or_email = st.text_input("Username or Email")
        password = st.text_input("Password", type="password")

        if st.button("Login", use_container_width=True):
            login_user(username_or_email, password)

    with tab2:
        st.subheader("Create Account")
        full_name = st.text_input("Full Name")
        username = st.text_input("Username", key="reg_user")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password", key="reg_pass")
        confirm_password = st.text_input("Confirm Password", type="password")

        if st.button("Create Account", use_container_width=True):
            create_account(full_name, username, email, password, confirm_password)


def dashboard_page():
    user = st.session_state.current_user
    user_name = user["full_name"] if user else "User"

    st.sidebar.title("IDS Dashboard")
    st.sidebar.caption(f"Signed in as: {user_name}")

    if st.sidebar.button("Logout"):
        st.session_state.logged_in = False
        st.session_state.current_user = None
        st.rerun()

    st.sidebar.header("Detection Settings")
    st.sidebar.number_input("Time Window (seconds)", min_value=1, value=10)
    st.sidebar.number_input("Port Threshold", min_value=1, value=10)
    st.sidebar.number_input("SYN Threshold", min_value=1, value=20)
    st.sidebar.number_input("ICMP Threshold", min_value=1, value=15)

    st.markdown('<div class="main-title">Intrusion Detection System</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="subtitle">Web-based IDS dashboard with live monitoring display and attack simulation controls.</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div class="hero">
            <h3>Network Monitoring Dashboard</h3>
            <p>
                Start the IDS dashboard to display live packet activity and simulate suspicious attacks.
                The dashboard shows packet logs, alerts, statistics, and suspicious IPs in a professional web interface.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

    col_start, col_stop, col_clear = st.columns(3)

    with col_start:
        if st.button("Start IDS", use_container_width=True):
            st.session_state.ids_running = True
            add_output("IDS started successfully.")
            add_output("The system is now monitoring network traffic.")
            add_output("-" * 70)

    with col_stop:
        if st.button("Stop IDS", use_container_width=True):
            st.session_state.ids_running = False
            add_output("-" * 70)
            add_output("IDS stopped.")

    with col_clear:
        if st.button("Clear Output", use_container_width=True):
            st.session_state.output = []
            st.session_state.packets = []
            st.session_state.alerts = []
            st.session_state.suspicious_ips = set()
            st.session_state.protocol_stats = {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0}
            st.session_state.attack_stats = {"Port Scan": 0, "SYN Flood": 0, "ICMP Flood": 0}

    st.divider()

    col_a, col_b, col_c = st.columns(3)

    with col_a:
        if st.button("Simulate Port Scan", use_container_width=True):
            simulate_port_scan()
            st.rerun()

    with col_b:
        if st.button("Simulate SYN Flood", use_container_width=True):
            simulate_syn_flood()
            st.rerun()

    with col_c:
        if st.button("Simulate ICMP Flood", use_container_width=True):
            simulate_icmp_flood()
            st.rerun()

    generate_live_traffic()

    status = "Running" if st.session_state.ids_running else "Stopped"
    status_icon = "🟢" if st.session_state.ids_running else "🔴"

    st.subheader(f"{status_icon} IDS Status: {status}")

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Packets Captured", len(st.session_state.packets))
    m2.metric("Alerts", len(st.session_state.alerts))
    m3.metric("Suspicious IPs", len(st.session_state.suspicious_ips))
    m4.metric("TCP Packets", st.session_state.protocol_stats["TCP"])

    if st.session_state.alerts:
        st.markdown(
            f'<div class="alert-box">{st.session_state.alerts[-1]}</div>',
            unsafe_allow_html=True
        )
    else:
        st.markdown(
            '<div class="success-box">No suspicious activity detected yet.</div>',
            unsafe_allow_html=True
        )

    left, right = st.columns(2)

    with left:
        st.subheader("Protocol Statistics")
        protocol_df = pd.DataFrame(
            list(st.session_state.protocol_stats.items()),
            columns=["Protocol", "Count"]
        )
        st.dataframe(protocol_df, use_container_width=True)
        st.bar_chart(protocol_df.set_index("Protocol"))

    with right:
        st.subheader("Attack Statistics")
        attack_df = pd.DataFrame(
            list(st.session_state.attack_stats.items()),
            columns=["Attack Type", "Count"]
        )
        st.dataframe(attack_df, use_container_width=True)
        st.bar_chart(attack_df.set_index("Attack Type"))

    st.subheader("IDS Output")
    terminal_text = "\n".join(st.session_state.output[-120:])
    st.markdown(f'<div class="terminal">{terminal_text}</div>', unsafe_allow_html=True)

    st.subheader("Captured Packets")

    if st.session_state.packets:
        packets_df = pd.DataFrame(st.session_state.packets)
        st.dataframe(packets_df.tail(50), use_container_width=True)
    else:
        st.info("No packets captured yet. Press Start IDS to begin monitoring.")

    st.subheader("Suspicious IPs")

    if st.session_state.suspicious_ips:
        st.dataframe(
            pd.DataFrame(sorted(list(st.session_state.suspicious_ips)), columns=["Suspicious IP"]),
            use_container_width=True
        )
    else:
        st.info("No suspicious IPs detected yet.")

    if st.session_state.ids_running:
        time.sleep(1)
        st.rerun()


def main():
    init_state()

    if not st.session_state.logged_in:
        login_page()
    else:
        dashboard_page()


if __name__ == "__main__":
    main()
