"""Read-only dashboard for Suricata EVE alert logs."""
from pathlib import Path
import sys
import pandas as pd
import streamlit as st
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from alert_parser import load_alerts

st.set_page_config(page_title="CodeAlpha NIDS", page_icon="🛡️", layout="wide")
st.title("🛡️ Network Intrusion Detection Dashboard")
st.caption("Suricata EVE JSON | read-only alert monitoring | lab demonstrations")
source = st.sidebar.text_input("EVE JSON path", str(Path(__file__).resolve().parents[1] / "sample_data" / "sample_eve.json"))
max_lines = st.sidebar.slider("Maximum log lines", 100, 100000, 10000, 100)
if st.sidebar.button("Refresh alerts"):
    st.rerun()
try:
    alerts = load_alerts(source, max_lines)
except (OSError, ValueError) as exc:
    st.error(f"Cannot read log: {exc}")
    st.stop()
if not alerts:
    st.info("No alert events found. Check the log path or generate authorized test traffic.")
    st.stop()
df = pd.DataFrame(alerts)
severities = sorted(df["severity"].dropna().astype(str).unique())
selected = st.sidebar.multiselect("Severity (Suricata: 1 = highest)", severities, default=severities)
df = df[df["severity"].astype(str).isin(selected)]
a,b,c = st.columns(3)
a.metric("Alerts", len(df))
b.metric("Unique source IPs", df["src_ip"].nunique())
c.metric("Unique signatures", df["signature"].nunique())
st.subheader("Top detection signatures")
st.bar_chart(df["signature"].value_counts())
st.subheader("Alerts by protocol")
st.bar_chart(df["proto"].value_counts())
st.subheader("Alert details")
st.dataframe(df, use_container_width=True, hide_index=True)
st.download_button("Export filtered CSV", df.to_csv(index=False).encode("utf-8"), "nids_alerts.csv", "text/csv")
st.warning("Alerts indicate potential threats, not proof of compromise. Validate before responding.")
