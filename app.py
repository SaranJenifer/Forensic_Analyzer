import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt

st.title("🔎 AI-Based Digital Forensics Analyzer")

st.subheader("Upload Log File")

uploaded_file = st.file_uploader("Upload a log file", type=["csv"])

if uploaded_file is not None:

    data = pd.read_csv(uploaded_file)

    st.subheader("📄 Log Data Preview")
    st.dataframe(data)

    # -----------------------------
    # LOG SUMMARY
    # -----------------------------
    st.subheader("📊 Log Summary")

    total_logs = len(data)
    unique_users = data["user"].nunique()
    unique_ips = data["ip"].nunique()
    failed_logins = len(data[data["action"] == "failed_login"])

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Logs", total_logs)
    col2.metric("Unique Users", unique_users)
    col3.metric("Unique IPs", unique_ips)
    col4.metric("Failed Logins", failed_logins)

    # -----------------------------
    # FILTER SECTION
    # -----------------------------
    st.subheader("🔍 Filter Logs")

    user_filter = st.selectbox("Select User", ["All"] + list(data["user"].unique()))
    ip_filter = st.selectbox("Select IP", ["All"] + list(data["ip"].unique()))
    action_filter = st.selectbox("Select Action", ["All"] + list(data["action"].unique()))

    filtered_data = data.copy()

    if user_filter != "All":
        filtered_data = filtered_data[filtered_data["user"] == user_filter]

    if ip_filter != "All":
        filtered_data = filtered_data[filtered_data["ip"] == ip_filter]

    if action_filter != "All":
        filtered_data = filtered_data[filtered_data["action"] == action_filter]

    st.subheader("Filtered Logs")
    st.dataframe(filtered_data)

    # -----------------------------
    # ACTIVITY CHART
    # -----------------------------
    st.subheader("📈 Activity Chart")

    action_counts = data["action"].value_counts()

    fig, ax = plt.subplots()
    ax.bar(action_counts.index, action_counts.values)
    ax.set_xlabel("Action Type")
    ax.set_ylabel("Count")
    ax.set_title("User Activity Distribution")

    st.pyplot(fig)

    # -----------------------------
    # DOWNLOAD REPORT
    # -----------------------------
    st.subheader("📥 Download Evidence Report")

    csv = filtered_data.to_csv(index=False).encode('utf-8')

    st.download_button(
        label="Download Filtered Logs",
        data=csv,
        file_name="forensic_report.csv",
        mime="text/csv",
    )

