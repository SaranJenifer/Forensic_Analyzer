import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import base64

# -----------------------------
# PAGE SETTINGS
# -----------------------------
st.set_page_config(page_title="Digital Forensics Analyzer", layout="wide")

# -----------------------------
# BACKGROUND FUNCTION
# -----------------------------
def set_background(image_file):
    with open(image_file, "rb") as img:
        encoded = base64.b64encode(img.read()).decode()

    page_bg = f"""
    <style>
    .stApp {{
        background-image: url("data:image/jpg;base64,{encoded}");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
    }}

    .stApp::before {{
        content: "";
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0,0,0,0.6);
        z-index: -1;
    }}

    [data-testid="metric-container"] {{
        background: rgba(255,255,255,0.08);
        border-radius: 10px;
        padding: 10px;
        border: 1px solid rgba(255,255,255,0.2);
    }}
    </style>
    """

    st.markdown(page_bg, unsafe_allow_html=True)


# -----------------------------
# APPLY BACKGROUND
# -----------------------------
set_background("background.jpg")

# -----------------------------
# TITLE
# -----------------------------
st.title("🔎 AI-Based Digital Forensics Analyzer")

# -----------------------------
# SAMPLE LOG DOWNLOAD
# -----------------------------
st.subheader("Test the System with Sample Data")

with open("dataset/sample_logs.csv", "rb") as file:
    st.download_button(
        label="⬇ Download Sample Log File",
        data=file,
        file_name="sample_logs.csv",
        mime="text/csv"
    )

# -----------------------------
# SAMPLE DATA BUTTON
# -----------------------------
if st.button("Load Sample Logs"):
    data = pd.read_csv("dataset/sample_logs.csv")

# -----------------------------
# UPLOAD FILE
# -----------------------------
st.header("Upload Log File")

uploaded_file = st.file_uploader(
    "Upload CSV Log File",
    type=["csv"],
    key="log_uploader"
)

# -----------------------------
# PROCESS DATA
# -----------------------------
if uploaded_file is not None:

    data = pd.read_csv(uploaded_file)

if 'data' in locals():

    # -----------------------------
    # LOG SUMMARY
    # -----------------------------
    st.header("Log Summary")

    total_logs = len(data)
    users = data["user"].nunique()
    ips = data["ip"].nunique()
    failed = len(data[data["action"] == "failed_login"])

    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Total Logs", total_logs)
    c2.metric("Users", users)
    c3.metric("IPs", ips)
    c4.metric("Failed Logins", failed)

    # -----------------------------
    # ACTIVITY CHART
    # -----------------------------
    
    st.header("Activity Chart")

    col1 ,col2 ,col3 =st.columns([1,2,1])

    with col2:
        action_counts = data["action"].value_counts()

        fig, ax = plt.subplots(figsize=(3,2))
        ax.bar(action_counts.index, action_counts.values)

        ax.set_xlabel("Action")
        ax.set_ylabel("Count")

        st.pyplot(fig)

    # -----------------------------
    # SECURITY ANALYSIS
    # -----------------------------
    st.header("Security Analysis")

    st.subheader("🚨 Suspicious Activity Detection")

    failed_counts = data[data["action"] == "failed_login"].groupby("ip").size()

    suspicious_ips = failed_counts[failed_counts >= 3]

    if not suspicious_ips.empty:

        st.error("Possible Brute Force Attack Detected")

        suspicious_table = suspicious_ips.reset_index()
        suspicious_table.columns = ["IP Address", "Failed Attempts"]

        st.dataframe(suspicious_table)

    else:
        st.success("No suspicious activity detected")

    # -----------------------------
    # CHARTS
    # -----------------------------
    c1, c2 = st.columns(2)

    # Top IP Activity
    with c1:

        st.subheader("Top IP Activity")

        ip_counts = data["ip"].value_counts()

        fig, ax = plt.subplots(figsize=(4,3))

        ax.bar(ip_counts.index, ip_counts.values)
        ax.set_xticklabels(ip_counts.index, rotation=45)

        ax.set_xlabel("IP Address")
        ax.set_ylabel("Requests")

        st.pyplot(fig)

    # Activity Timeline
    with c2:

        st.subheader("Activity Timeline")

        timeline = data.groupby("timestamp").size()

        fig, ax = plt.subplots(figsize=(4,3))

        ax.plot(timeline.index, timeline.values)

        ax.set_xlabel("Time")
        ax.set_ylabel("Activity Count")

        st.pyplot(fig)

    # -----------------------------
    # FILTER + TABLE
    # -----------------------------
    st.header("Logs")

    left, right = st.columns([1,2])

    # FILTERS
    with left:

        st.subheader("Filters")

        user_filter = st.selectbox(
            "User",
            ["All"] + list(data["user"].unique())
        )

        ip_filter = st.selectbox(
            "IP Address",
            ["All"] + list(data["ip"].unique())
        )

        action_filter = st.selectbox(
            "Action",
            ["All"] + list(data["action"].unique())
        )

    # FILTER DATA
    filtered_data = data.copy()

    if user_filter != "All":
        filtered_data = filtered_data[filtered_data["user"] == user_filter]

    if ip_filter != "All":
        filtered_data = filtered_data[filtered_data["ip"] == ip_filter]

    if action_filter != "All":
        filtered_data = filtered_data[filtered_data["action"] == action_filter]

    # TABLE
    with right:

        st.subheader("Filtered Logs")
        st.dataframe(filtered_data, use_container_width=True)

    # -----------------------------
    # DOWNLOAD REPORT
    # -----------------------------
    st.header("Download Report")

    csv = filtered_data.to_csv(index=False).encode("utf-8")

    st.download_button(
        label="Download Filtered Logs",
        data=csv,
        file_name="forensic_report.csv",
        mime="text/csv"
    )