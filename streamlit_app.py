import streamlit as st
import threading
import queue
import time
import json
import os
import hashlib
import pandas as pd
from ids import MiniIDS


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
            return True

    st.error("Invalid username/email or password.")
    return False


def initialize_state():
    defaults = {
        "logged_in": False,
        "current_user": None,
        "page": "login",
        "ids": None,
        "ids_thread": None,
        "running": False,
        "messages": [],
        "log_queue": queue.Queue()
    }

    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def add_message(message):
    st.session_state.log_queue.put(message)


def drain_messages():
    while not st.session_state.log_queue.empty():
        message = st.session_state.log_queue.get()
        st.session_state.messages.append(message)

    if len(st.session_state.messages) > 300:
        st.session_state.messages = st.session_state.messages[-300:]


def start_ids(time_window, port_threshold, syn_threshold, icmp_threshold, entropy_threshold, entropy_min_ports):
    if st.session_state.running:
        st.warning("IDS is already running.")
        return

    st.session_state.messages = []
    st.session_state.log_queue = queue.Queue()

    ids = MiniIDS(
        time_window=time_window,
        port_threshold=port_threshold,
        syn_threshold=syn_threshold,
        icmp_threshold=icmp_threshold,
        entropy_threshold=entropy_threshold,
        entropy_min_ports=entropy_min_ports,
        log_file="streamlit_ids_alerts.log",
        csv_file="streamlit_packets_log.csv",
        output_callback=add_message,
        alert_callback=add_message
    )

    thread = threading.Thread(target=ids.sniff_packets, daemon=True)
    thread.start()

    st.session_state.ids = ids
    st.session_state.ids_thread = thread
    st.session_state.running = True

    add_message("IDS started successfully.")
    add_message("The system is now monitoring real network packets from this device.")
    add_message("-" * 80)


def stop_ids():
    if st.session_state.ids is not None and st.session_state.running:
        st.session_state.ids.stop()
        st.session_state.running = False
        add_message("-" * 80)
        add_message("IDS stopped.")
    else:
        st.info("IDS is not running.")


def login_page():
    st.markdown(
        """
        <style>
        .main {
            background-color: #F3F6FB;
        }
        .login-title {
            font-size: 42px;
            font-weight: 800;
            color: #0F172A;
            text-align: center;
            margin-top: 30px;
        }
        .login-subtitle {
            font-size: 18px;
            color: #64748B;
            text-align: center;
            margin-bottom: 30px;
        }
        </style>
        """,
        unsafe_allow_html=True
    )

    st.markdown('<div class="login-title">Intrusion Detection System</div>', unsafe_allow_html=True)
    st.markdown('<div class="login-subtitle">Real-Time Network Packet Monitoring</div>', unsafe_allow_html=True)

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
    drain_messages()

    user = st.session_state.current_user
    user_name = user["full_name"] if user else "User"

    st.sidebar.title("IDS Dashboard")
    st.sidebar.caption(f"Signed in as: {user_name}")

    if st.sidebar.button("Logout"):
        if st.session_state.ids is not None and st.session_state.running:
            st.session_state.ids.stop()

        st.session_state.logged_in = False
        st.session_state.current_user = None
        st.session_state.running = False
        st.rerun()

    st.title("Intrusion Detection System")
    st.caption("Real-time packet monitoring using Scapy + Rule-Based Detection + Sliding Window + Entropy Algorithm")

    with st.sidebar:
        st.header("Detection Settings")

        time_window = st.number_input("Time Window (seconds)", min_value=1, value=10)
        port_threshold = st.number_input("Port Threshold", min_value=1, value=10)
        syn_threshold = st.number_input("SYN Threshold", min_value=1, value=20)
        icmp_threshold = st.number_input("ICMP Threshold", min_value=1, value=15)

        st.header("Entropy Algorithm")
        entropy_threshold = st.number_input("Entropy Threshold", min_value=0.1, value=2.0, step=0.1)
        entropy_min_ports = st.number_input("Entropy Min Unique Ports", min_value=2, value=5)

        st.divider()

        col_a, col_b = st.columns(2)

        with col_a:
            if st.button("Start IDS", use_container_width=True):
                start_ids(
                    int(time_window),
                    int(port_threshold),
                    int(syn_threshold),
                    int(icmp_threshold),
                    float(entropy_threshold),
                    int(entropy_min_ports)
                )
                st.rerun()

        with col_b:
            if st.button("Stop IDS", use_container_width=True):
                stop_ids()
                st.rerun()

        if st.button("Refresh Dashboard", use_container_width=True):
            st.rerun()

    status = "Running" if st.session_state.running else "Stopped"
    status_color = "🟢" if st.session_state.running else "🔴"

    st.subheader(f"{status_color} IDS Status: {status}")

    stats = None

    if st.session_state.ids is not None:
        stats = st.session_state.ids.get_stats()
    else:
        stats = {
            "packet_count": 0,
            "alert_count": 0,
            "protocol_stats": {"TCP": 0, "UDP": 0, "ICMP": 0, "OTHER": 0},
            "attack_stats": {"Port Scan": 0, "SYN Flood": 0, "ICMP Flood": 0, "Entropy Port Scan": 0},
            "suspicious_ips": [],
            "alert_history": []
        }

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Packets Captured", stats["packet_count"])
    col2.metric("Alerts", stats["alert_count"])
    col3.metric("Suspicious IPs", len(stats["suspicious_ips"]))
    col4.metric("Entropy Alerts", stats["attack_stats"].get("Entropy Port Scan", 0))

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Protocol Statistics")
        protocol_df = pd.DataFrame(
            list(stats["protocol_stats"].items()),
            columns=["Protocol", "Count"]
        )
        st.dataframe(protocol_df, use_container_width=True)

        st.bar_chart(protocol_df.set_index("Protocol"))

    with right:
        st.subheader("Attack Statistics")
        attack_df = pd.DataFrame(
            list(stats["attack_stats"].items()),
            columns=["Attack Type", "Count"]
        )
        st.dataframe(attack_df, use_container_width=True)

        st.bar_chart(attack_df.set_index("Attack Type"))

    st.divider()

    st.subheader("Suspicious IPs")

    if stats["suspicious_ips"]:
        st.dataframe(
            pd.DataFrame(stats["suspicious_ips"], columns=["Suspicious IP"]),
            use_container_width=True
        )
    else:
        st.info("No suspicious IPs detected yet.")

    st.subheader("Live IDS Output")

    output_text = "\n".join(st.session_state.messages[-120:])

    st.text_area(
        "Output",
        value=output_text,
        height=350,
        label_visibility="collapsed"
    )

    if os.path.exists("streamlit_packets_log.csv"):
        st.subheader("Captured Packets CSV Preview")

        try:
            df = pd.read_csv("streamlit_packets_log.csv")
            st.dataframe(df.tail(30), use_container_width=True)
        except Exception:
            st.info("CSV file exists but cannot be displayed yet.")

    if st.session_state.running:
        time.sleep(1)
        st.rerun()


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
