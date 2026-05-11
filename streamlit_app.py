import streamlit as st
import pandas as pd
import hashlib
import json
import os
import math
from collections import Counter


USERS_FILE = "streamlit_users.json"


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
    full_name = full_name.strip()
    username = username.strip()
    email = email.strip()
    password = password.strip()
    confirm_password = confirm_password.strip()

    if not full_name or not username or not email or not password or not confirm_password:
        st.error("Please fill in all fields.")
        return False

    if "@" not in email or "." not in email:
        st.error("Please enter a valid email address.")
        return False

    if len(password) < 4:
        st.error("Password must be at least 4 characters.")
        return False

    if password != confirm_password:
        st.error("Passwords do not match.")
        return False

    users = load_users()

    for user in users:
        if user["username"].lower() == username.lower():
            st.error("Username already exists.")
            return False

        if user["email"].lower() == email.lower():
            st.error("Email already exists.")
            return False

    users.append({
        "full_name": full_name,
        "username": username,
        "email": email,
        "password": hash_password(password)
    })

    save_users(users)
    st.success("Account created successfully. You can now login.")
    return True


def login_user(username_or_email, password):
    users = load_users()
    hashed_password = hash_password(password)

    for user in users:
        username_match = user["username"].lower() == username_or_email.lower()
        email_match = user["email"].lower() == username_or_email.lower()
        password_match = user["password"] == hashed_password

        if (username_match or email_match) and password_match:
            st.session_state.logged_in = True
            st.session_state.current_user = user
            st.rerun()

    st.error("Invalid username/email or password.")
    return False


def initialize_state():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False

    if "current_user" not in st.session_state:
        st.session_state.current_user = None


def calculate_entropy(values):
    values = [v for v in values if pd.notna(v)]

    if not values:
        return 0.0

    counts = Counter(values)
    total = len(values)

    entropy = 0.0

    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy


def analyze_packets(df, port_threshold, syn_threshold, icmp_threshold, entropy_threshold, entropy_min_ports):
    required_columns = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "protocol",
        "src_port",
        "dst_port",
        "flags",
        "packet_length"
    ]

    missing = [col for col in required_columns if col not in df.columns]

    if missing:
        st.error(f"CSV file is missing required columns: {missing}")
        return None

    df = df.copy()

    df["protocol"] = df["protocol"].astype(str)
    df["src_ip"] = df["src_ip"].astype(str)
    df["dst_ip"] = df["dst_ip"].astype(str)
    df["flags"] = df["flags"].astype(str)
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")

    alerts = []
    suspicious_ips = set()

    protocol_stats = df["protocol"].value_counts().to_dict()

    attack_stats = {
        "Port Scan": 0,
        "SYN Flood": 0,
        "ICMP Flood": 0,
        "Entropy Port Scan": 0
    }

    tcp_syn = df[
        (df["protocol"].str.upper() == "TCP") &
        (df["flags"].str.upper() == "S")
    ]

    for src_ip, group in tcp_syn.groupby("src_ip"):
        dst_ports = group["dst_port"].dropna().astype(int).tolist()
        unique_ports = set(dst_ports)
        syn_count = len(group)
        entropy_score = calculate_entropy(dst_ports)

        if len(unique_ports) >= entropy_min_ports and entropy_score >= entropy_threshold:
            suspicious_ips.add(src_ip)
            attack_stats["Entropy Port Scan"] += 1
            alerts.append({
                "Attack Type": "Entropy Port Scan",
                "Source IP": src_ip,
                "Details": f"Entropy={entropy_score:.2f}, Unique Ports={len(unique_ports)}"
            })

        elif len(unique_ports) >= port_threshold:
            suspicious_ips.add(src_ip)
            attack_stats["Port Scan"] += 1
            alerts.append({
                "Attack Type": "Port Scan",
                "Source IP": src_ip,
                "Details": f"{len(unique_ports)} different destination ports"
            })

        elif syn_count >= syn_threshold:
            suspicious_ips.add(src_ip)
            attack_stats["SYN Flood"] += 1
            alerts.append({
                "Attack Type": "SYN Flood",
                "Source IP": src_ip,
                "Details": f"{syn_count} SYN packets"
            })

    icmp_df = df[df["protocol"].str.upper() == "ICMP"]

    for src_ip, group in icmp_df.groupby("src_ip"):
        icmp_count = len(group)

        if icmp_count >= icmp_threshold:
            suspicious_ips.add(src_ip)
            attack_stats["ICMP Flood"] += 1
            alerts.append({
                "Attack Type": "ICMP Flood",
                "Source IP": src_ip,
                "Details": f"{icmp_count} ICMP packets"
            })

    return {
        "total_packets": len(df),
        "protocol_stats": protocol_stats,
        "attack_stats": attack_stats,
        "suspicious_ips": sorted(list(suspicious_ips)),
        "alerts": alerts,
        "df": df
    }


def login_page():
    st.markdown(
        """
        <div style="text-align:center; padding: 30px 0 20px 0;">
            <h1 style="font-size:48px; color:#0F172A;">Intrusion Detection System</h1>
            <p style="font-size:18px; color:#64748B;">Web Dashboard for Real Packet Traffic Analysis</p>
        </div>
        """,
        unsafe_allow_html=True
    )

    tab1, tab2 = st.tabs(["Login", "Create Account"])

    with tab1:
        st.subheader("Login")
        username_or_email = st.text_input("Username or Email", key="login_user")
        password = st.text_input("Password", type="password", key="login_pass")

        if st.button("Login", use_container_width=True):
            login_user(username_or_email, password)

    with tab2:
        st.subheader("Create Account")
        full_name = st.text_input("Full Name")
        username = st.text_input("Username")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
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

    port_threshold = st.sidebar.number_input("Port Threshold", min_value=1, value=10)
    syn_threshold = st.sidebar.number_input("SYN Threshold", min_value=1, value=20)
    icmp_threshold = st.sidebar.number_input("ICMP Threshold", min_value=1, value=15)

    st.sidebar.header("Entropy Algorithm")
    entropy_threshold = st.sidebar.number_input("Entropy Threshold", min_value=0.1, value=2.0, step=0.1)
    entropy_min_ports = st.sidebar.number_input("Entropy Min Unique Ports", min_value=2, value=5)

    st.title("Intrusion Detection System")
    st.caption("Rule-Based Detection + Sliding Window Concept + Entropy-Based Anomaly Detection")

    st.markdown(
        """
        Upload the real CSV packet log generated by the local IDS system.
        The uploaded file is analyzed using Port Scan, SYN Flood, ICMP Flood, and Entropy-Based detection.
        """
    )

    uploaded_file = st.file_uploader("Upload packets CSV file", type=["csv"])

    if uploaded_file is None:
        st.info("Upload the real packets CSV file generated from your local IDS, such as packets_log.csv.")
        return

    try:
        df = pd.read_csv(uploaded_file)
    except Exception as e:
        st.error(f"Could not read CSV file: {e}")
        return

    results = analyze_packets(
        df,
        int(port_threshold),
        int(syn_threshold),
        int(icmp_threshold),
        float(entropy_threshold),
        int(entropy_min_ports)
    )

    if results is None:
        return

    st.subheader("IDS Analysis Summary")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Packets Captured", results["total_packets"])
    col2.metric("Alerts", len(results["alerts"]))
    col3.metric("Suspicious IPs", len(results["suspicious_ips"]))
    col4.metric("Entropy Alerts", results["attack_stats"].get("Entropy Port Scan", 0))

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Protocol Statistics")
        protocol_df = pd.DataFrame(
            list(results["protocol_stats"].items()),
            columns=["Protocol", "Count"]
        )
        st.dataframe(protocol_df, use_container_width=True)
        st.bar_chart(protocol_df.set_index("Protocol"))

    with right:
        st.subheader("Attack Statistics")
        attack_df = pd.DataFrame(
            list(results["attack_stats"].items()),
            columns=["Attack Type", "Count"]
        )
        st.dataframe(attack_df, use_container_width=True)
        st.bar_chart(attack_df.set_index("Attack Type"))

    st.divider()

    st.subheader("Detected Alerts")

    if results["alerts"]:
        st.dataframe(pd.DataFrame(results["alerts"]), use_container_width=True)
    else:
        st.success("No suspicious activity detected based on the current thresholds.")

    st.subheader("Suspicious IPs")

    if results["suspicious_ips"]:
        st.dataframe(pd.DataFrame(results["suspicious_ips"], columns=["Suspicious IP"]), use_container_width=True)
    else:
        st.info("No suspicious IPs detected.")

    st.subheader("Captured Packets Preview")
    st.dataframe(results["df"].tail(50), use_container_width=True)


def main():
    st.set_page_config(
        page_title="Intrusion Detection System",
        page_icon="🛡️",
        layout="wide"
    )

    initialize_state()

    if not st.session_state.logged_in:
        login_page()
    else:
        dashboard_page()


if __name__ == "__main__":
    main()
