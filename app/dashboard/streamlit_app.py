"""
app/dashboard/streamlit_app.py — Interactive Streamlit dashboard.

Run with:
    streamlit run app/dashboard/streamlit_app.py

Make sure the FastAPI backend is running at http://localhost:8000
before starting the dashboard.
"""
import io
import json
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

# ─── Configuration ─────────────────────────────────────────────
API_BASE = "http://localhost:8000"
API_V1 = f"{API_BASE}/api/v1"

st.set_page_config(
    page_title="CyberSec AI — Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ────────────────────────────────────────────────
st.markdown("""
<style>
/* Import Google Font */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

/* Global font */
html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

/* Sidebar styling */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0f172a 0%, #1e293b 100%);
    border-right: 1px solid #334155;
}
section[data-testid="stSidebar"] * {
    color: #e2e8f0 !important;
}
section[data-testid="stSidebar"] .stRadio > label {
    color: #94a3b8 !important;
    font-size: 0.85rem;
    letter-spacing: 0.05em;
    text-transform: uppercase;
}

/* KPI Card styling */
div[data-testid="metric-container"] {
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 16px;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
}
div[data-testid="metric-container"] > label {
    color: #94a3b8 !important;
    font-size: 0.8rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
}
div[data-testid="metric-container"] > div {
    color: #f1f5f9 !important;
    font-size: 2rem;
    font-weight: 700;
}

/* Header gradient */
.hero-header {
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 50%, #0f172a 100%);
    border: 1px solid #1e40af;
    border-radius: 16px;
    padding: 24px 32px;
    margin-bottom: 24px;
    box-shadow: 0 0 40px rgba(37, 99, 235, 0.15);
}

/* Severity badges */
.severity-high {
    background: linear-gradient(135deg, #7f1d1d, #991b1b);
    color: #fca5a5;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    border: 1px solid #ef4444;
}
.severity-suspicious {
    background: linear-gradient(135deg, #78350f, #92400e);
    color: #fcd34d;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    border: 1px solid #f59e0b;
}
.severity-normal {
    background: linear-gradient(135deg, #052e16, #14532d);
    color: #86efac;
    padding: 3px 10px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 600;
    border: 1px solid #22c55e;
}

/* Alert box for important messages */
.info-box {
    background: linear-gradient(135deg, #0c1a2e, #0e3a5f);
    border: 1px solid #1d4ed8;
    border-left: 4px solid #3b82f6;
    border-radius: 8px;
    padding: 16px;
    margin: 8px 0;
    color: #bfdbfe;
}

/* Status dot */
.status-dot-green { color: #22c55e; }
.status-dot-red { color: #ef4444; }
.status-dot-yellow { color: #f59e0b; }
</style>
""", unsafe_allow_html=True)


# ─── API Helper Functions ──────────────────────────────────────

@st.cache_data(ttl=30)
def get_summary():
    """Fetch summary KPIs from API."""
    try:
        r = requests.get(f"{API_V1}/summary", timeout=5)
        if r.status_code == 200:
            return r.json(), None
        return None, f"API error {r.status_code}: {r.text[:200]}"
    except requests.exceptions.ConnectionError:
        return None, "Cannot connect to API. Is the backend running? Run: uvicorn app.main:app --reload --port 8000"
    except Exception as e:
        return None, str(e)


@st.cache_data(ttl=30)
def get_health():
    """Fetch health status from API."""
    try:
        r = requests.get(f"{API_BASE}/health", timeout=5)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


@st.cache_data(ttl=30)
def get_events(page=1, per_page=50, severity=None, is_anomaly=None):
    """Fetch events from API with optional filters."""
    try:
        params = {"page": page, "per_page": per_page}
        if severity:
            params["severity"] = severity
        if is_anomaly is not None:
            params["is_anomaly"] = str(is_anomaly).lower()
        r = requests.get(f"{API_V1}/events", params=params, timeout=10)
        if r.status_code == 200:
            return r.json(), None
        return None, f"API error {r.status_code}"
    except Exception as e:
        return None, str(e)


@st.cache_data(ttl=60)
def get_model_metrics():
    """Fetch model metrics from API."""
    try:
        r = requests.get(f"{API_V1}/model/metrics", timeout=5)
        if r.status_code == 200:
            return r.json(), None
        elif r.status_code == 404:
            return None, "No model trained yet. Run: python scripts/train_model.py"
        return None, f"API error {r.status_code}"
    except Exception as e:
        return None, str(e)


def clear_cache():
    """Clear all cached data."""
    get_summary.clear()
    get_health.clear()
    get_events.clear()
    get_model_metrics.clear()


# ─── Sidebar ───────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style="text-align: center; padding: 8px 0 16px 0;">
        <span style="font-size: 2.5rem;">🛡️</span>
        <h2 style="margin: 4px 0; font-size: 1.1rem; color: #e2e8f0;">CyberSec AI</h2>
        <p style="margin: 0; font-size: 0.75rem; color: #64748b;">Threat Detection System</p>
    </div>
    """, unsafe_allow_html=True)

    st.divider()

    page = st.radio(
        "NAVIGATION",
        [
            "📊 Overview Dashboard",
            "📁 Upload & Analyze",
            "🔍 Detection Events",
            "🤖 Model Training",
            "📖 API Documentation",
        ],
        label_visibility="visible",
    )

    st.divider()

    # Health status indicator
    health = get_health()
    if health:
        db_status = "🟢 Online" if health.get("database_ok") else "🔴 Error"
        model_status = "🟢 Loaded" if health.get("model_loaded") else "🟡 Not trained"
        st.markdown(f"""
        **System Status**
        - Database: {db_status}
        - ML Model: {model_status}
        - Events: {health.get('total_events', 0):,}
        """)
    else:
        st.error("⚠️ Backend offline")

    st.divider()
    if st.button("🔄 Refresh Data", use_container_width=True):
        clear_cache()
        st.rerun()

    st.markdown("""
    <div style="margin-top: 16px; padding: 8px; border: 1px solid #334155; border-radius: 8px;
                background: rgba(255,255,255,0.02); font-size: 0.75rem; color: #64748b;">
        <strong style="color: #94a3b8;">⚠️ Data Disclaimer</strong><br>
        All demo data is <em>synthetic</em> and does not represent real financial institution data.
    </div>
    """, unsafe_allow_html=True)


# ═══════════════════════════════════════════════════════════════
# PAGE 1: Overview Dashboard
# ═══════════════════════════════════════════════════════════════

if page == "📊 Overview Dashboard":
    st.markdown("""
    <div class="hero-header">
        <h1 style="margin: 0; font-size: 1.8rem; color: #f1f5f9;">
            🛡️ Cybersecurity Threat Detection Dashboard
        </h1>
        <p style="margin: 8px 0 0 0; color: #94a3b8; font-size: 0.95rem;">
            AI-Based Threat Identification in Financial Institutions
        </p>
    </div>
    """, unsafe_allow_html=True)

    summary, error = get_summary()

    if error:
        st.error(f"**Cannot load dashboard data.**\n\n{error}")
        st.info("Make sure the FastAPI backend is running:\n```\nuvicorn app.main:app --reload --port 8000\n```")
        st.stop()

    if not summary:
        st.warning("No data available yet. Initialize the database and upload data.")
        st.stop()

    # ── KPI Cards ──────────────────────────────────────────────
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.metric("Total Events", f"{summary['total_events']:,}")
    with c2:
        st.metric("Anomalies Detected", f"{summary['total_anomalies']:,}",
                  delta=f"{summary['anomaly_rate_pct']:.1f}% rate",
                  delta_color="inverse")
    with c3:
        st.metric("High Severity", f"{summary['high_severity_count']:,}",
                  delta=None)
    with c4:
        st.metric("Suspicious", f"{summary['suspicious_count']:,}")
    with c5:
        st.metric("Datasets Imported", f"{summary['total_datasets_imported']:,}")

    st.divider()

    # ── Charts Row 1 ───────────────────────────────────────────
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Normal vs Anomalous Events")
        normal_count = summary["total_normal"]
        anomaly_count = summary["total_anomalies"]

        if summary["total_events"] == 0:
            st.info("No events yet. Upload a dataset to see distribution.")
        else:
            fig = go.Figure(data=[go.Pie(
                labels=["Normal", "Suspicious", "High Severity"],
                values=[
                    normal_count,
                    summary["suspicious_count"],
                    summary["high_severity_count"],
                ],
                hole=0.55,
                marker=dict(
                    colors=["#22c55e", "#f59e0b", "#ef4444"],
                    line=dict(color="#0f172a", width=2),
                ),
                textfont=dict(size=13),
            )])
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e2e8f0"),
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=-0.15, x=0.5, xanchor="center"),
                margin=dict(t=20, b=20, l=0, r=0),
                height=320,
                annotations=[dict(
                    text=f"{summary['anomaly_rate_pct']:.1f}%<br>Anomaly Rate",
                    font=dict(size=14, color="#94a3b8"),
                    showarrow=False,
                )],
            )
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        st.subheader("Severity Distribution")
        events_data, _ = get_events(per_page=200)
        if events_data and events_data.get("events"):
            df_events = pd.DataFrame(events_data["events"])
            sev_counts = df_events["severity"].value_counts().reset_index()
            sev_counts.columns = ["Severity", "Count"]
            severity_order = {"High": 3, "Suspicious": 2, "Normal": 1}
            sev_counts["Order"] = sev_counts["Severity"].map(severity_order)
            sev_counts = sev_counts.sort_values("Order", ascending=False)

            color_map = {"High": "#ef4444", "Suspicious": "#f59e0b", "Normal": "#22c55e"}
            fig2 = px.bar(
                sev_counts, x="Severity", y="Count",
                color="Severity",
                color_discrete_map=color_map,
                text="Count",
            )
            fig2.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e2e8f0"),
                showlegend=False,
                margin=dict(t=20, b=20, l=0, r=0),
                height=320,
                xaxis=dict(gridcolor="#1e293b"),
                yaxis=dict(gridcolor="#1e293b"),
            )
            fig2.update_traces(textposition="outside", textfont_color="#e2e8f0")
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No events yet.")

    # ── Recent Events Table ────────────────────────────────────
    st.subheader("Recent Detection Events")
    events_data, error = get_events(per_page=10)
    if error:
        st.error(f"Could not load events: {error}")
    elif events_data and events_data.get("events"):
        df_recent = pd.DataFrame(events_data["events"])
        display_cols = [
            "id", "timestamp", "source_ip", "protocol",
            "severity", "is_anomaly", "anomaly_score", "alert_reason"
        ]
        display_cols = [c for c in display_cols if c in df_recent.columns]
        df_display = df_recent[display_cols].copy()

        if "timestamp" in df_display.columns:
            df_display["timestamp"] = pd.to_datetime(df_display["timestamp"]).dt.strftime("%Y-%m-%d %H:%M")
        if "anomaly_score" in df_display.columns:
            df_display["anomaly_score"] = df_display["anomaly_score"].apply(
                lambda x: f"{x:.4f}" if x is not None else "N/A"
            )
        if "alert_reason" in df_display.columns:
            df_display["alert_reason"] = df_display["alert_reason"].str[:80] + "..."

        # Color rows by severity
        def color_severity(val):
            if val == "High":
                return "background-color: #450a0a; color: #fca5a5"
            elif val == "Suspicious":
                return "background-color: #422006; color: #fcd34d"
            return "background-color: #052e16; color: #86efac"

        styled = df_display.style.applymap(color_severity, subset=["severity"])
        st.dataframe(styled, use_container_width=True, hide_index=True)

        # Model info
        if summary.get("model_trained"):
            st.success("✅ ML model is trained and active.")
        else:
            st.warning(
                "⚠️ No trained model found. Results are rule-based. "
                "Train a model: `python scripts/train_model.py`"
            )
    else:
        st.info("No events detected yet. Upload a dataset or use the Analyze page.")


# ═══════════════════════════════════════════════════════════════
# PAGE 2: Upload & Analyze
# ═══════════════════════════════════════════════════════════════

elif page == "📁 Upload & Analyze":
    st.title("📁 Dataset Upload & Analysis")

    tab1, tab2 = st.tabs(["📤 Upload CSV", "⚡ Analyze Sample Data"])

    with tab1:
        st.markdown("""
        <div class="info-box">
        <strong>📋 Expected CSV Format</strong><br>
        The CSV should contain some of these columns:<br>
        <code>failed_logins, bytes_in, bytes_out, connection_duration, protocol, unusual_hour, port_number</code><br>
        Optional: <code>source_ip, dest_ip, label (0=normal, 1=anomaly)</code><br>
        Missing columns are imputed automatically.
        </div>
        """, unsafe_allow_html=True)

        uploaded_file = st.file_uploader(
            "Upload CSV file (max 10 MB)",
            type=["csv"],
            help="CSV files only. Max 10 MB.",
        )

        if uploaded_file:
            file_bytes = uploaded_file.read()
            st.success(f"✅ File loaded: **{uploaded_file.name}** ({len(file_bytes)/1024:.1f} KB)")

            # Preview
            try:
                df_preview = pd.read_csv(io.BytesIO(file_bytes))
                st.subheader("Dataset Preview")
                col_info1, col_info2, col_info3 = st.columns(3)
                with col_info1:
                    st.metric("Total Rows", len(df_preview))
                with col_info2:
                    st.metric("Columns", len(df_preview.columns))
                with col_info3:
                    has_labels = "label" in df_preview.columns
                    st.metric("Has Labels", "Yes" if has_labels else "No")

                st.dataframe(df_preview.head(10), use_container_width=True)

                if has_labels:
                    label_dist = df_preview["label"].value_counts()
                    st.info(f"Label distribution: {dict(label_dist)}")

                # Analyze button
                if st.button("🔍 Run Threat Analysis", type="primary", use_container_width=True):
                    with st.spinner("Analyzing... this may take a moment for large files."):
                        try:
                            resp = requests.post(
                                f"{API_V1}/analyze/csv",
                                files={"file": (uploaded_file.name, io.BytesIO(file_bytes), "text/csv")},
                                timeout=60,
                            )
                            if resp.status_code == 200:
                                result = resp.json()
                                clear_cache()

                                st.success("✅ Analysis complete!")

                                # Results KPIs
                                r1, r2, r3, r4 = st.columns(4)
                                r1.metric("Analyzed", result["total_analyzed"])
                                r2.metric("Anomalies", result["anomalies_detected"])
                                r3.metric("High Severity", result["high_severity"])
                                r4.metric("Model Used", result["model_used"])

                                if result.get("warning"):
                                    st.warning(f"⚠️ {result['warning']}")

                                # Events table
                                if result.get("events"):
                                    st.subheader("Detection Results (first 50 shown)")
                                    df_results = pd.DataFrame(result["events"])
                                    show_cols = ["id", "severity", "is_anomaly", "anomaly_score",
                                                "source_ip", "protocol", "failed_logins",
                                                "unusual_hour", "alert_reason"]
                                    show_cols = [c for c in show_cols if c in df_results.columns]
                                    st.dataframe(df_results[show_cols], use_container_width=True)

                                    # CSV download
                                    csv_export = df_results.to_csv(index=False).encode()
                                    st.download_button(
                                        "📥 Download Results CSV",
                                        data=csv_export,
                                        file_name="detection_results.csv",
                                        mime="text/csv",
                                    )
                            else:
                                error_detail = resp.json().get("detail", resp.text)
                                st.error(f"Analysis failed (HTTP {resp.status_code}): {error_detail}")
                        except requests.exceptions.ConnectionError:
                            st.error("Cannot connect to API backend. Is it running?\n`uvicorn app.main:app --reload --port 8000`")
                        except Exception as e:
                            st.error(f"Unexpected error: {e}")
            except Exception as e:
                st.error(f"Could not preview file: {e}")

    with tab2:
        st.subheader("Analyze with Sample Dataset")
        st.markdown("""
        Click below to analyze the built-in synthetic sample dataset.
        This uses the pre-generated `data/sample/network_events.csv` file.
        """)

        col_a, col_b = st.columns(2)
        with col_a:
            n_events = st.slider("Number of events to analyze", 10, 500, 100)
        with col_b:
            st.markdown("<br>", unsafe_allow_html=True)
            run_sample = st.button("▶️ Run Sample Analysis", type="primary", use_container_width=True)

        if run_sample:
            # Generate sample events inline
            import numpy as np
            rng = np.random.default_rng(42)
            sample_events = []
            for i in range(n_events):
                is_anomaly_sim = rng.random() < 0.12
                sample_events.append({
                    "source_ip": f"192.0.2.{rng.integers(1, 255)}",
                    "dest_ip": f"198.51.100.{rng.integers(1, 255)}",
                    "protocol": rng.choice(["TCP", "UDP", "HTTPS", "HTTP", "SSH"]),
                    "failed_logins": int(rng.integers(20, 80) if is_anomaly_sim else rng.poisson(0.5)),
                    "bytes_in": float(np.exp(rng.normal(8, 1.5))),
                    "bytes_out": float(np.exp(rng.normal(13, 2) if is_anomaly_sim else rng.normal(7, 1.5))),
                    "connection_duration": float(rng.exponential(300 if is_anomaly_sim else 30)),
                    "unusual_hour": bool(is_anomaly_sim and rng.random() > 0.4),
                    "port_number": int(rng.choice([4444, 6667, 9999] if is_anomaly_sim else [80, 443, 22, 53])),
                })

            with st.spinner(f"Analyzing {n_events} sample events..."):
                try:
                    resp = requests.post(
                        f"{API_V1}/analyze",
                        json={"events": sample_events},
                        timeout=30,
                    )
                    if resp.status_code == 200:
                        result = resp.json()
                        clear_cache()
                        st.success(f"✅ Analyzed {result['total_analyzed']} events!")

                        c1, c2, c3 = st.columns(3)
                        c1.metric("Anomalies", result["anomalies_detected"])
                        c2.metric("High Severity", result["high_severity"])
                        c3.metric("Model", result["model_used"])

                        if result.get("warning"):
                            st.warning(result["warning"])

                        if result.get("events"):
                            df_r = pd.DataFrame(result["events"])
                            show = ["severity", "is_anomaly", "anomaly_score", "protocol",
                                   "failed_logins", "unusual_hour", "port_number", "alert_reason"]
                            show = [c for c in show if c in df_r.columns]
                            st.dataframe(df_r[show].head(20), use_container_width=True)
                    else:
                        st.error(f"Error {resp.status_code}: {resp.json().get('detail', resp.text)}")
                except requests.exceptions.ConnectionError:
                    st.error("Cannot connect to API. Start the backend: `uvicorn app.main:app --reload --port 8000`")


# ═══════════════════════════════════════════════════════════════
# PAGE 3: Detection Events
# ═══════════════════════════════════════════════════════════════

elif page == "🔍 Detection Events":
    st.title("🔍 Detection Events")

    # Filters
    with st.expander("🔽 Filters", expanded=True):
        col_f1, col_f2, col_f3 = st.columns(3)
        with col_f1:
            sev_filter = st.selectbox(
                "Severity", ["All", "High", "Suspicious", "Normal"]
            )
        with col_f2:
            anomaly_filter = st.selectbox(
                "Anomaly Status", ["All", "Anomaly Only", "Normal Only"]
            )
        with col_f3:
            per_page = st.selectbox("Events per page", [20, 50, 100], index=0)

    severity_param = sev_filter if sev_filter != "All" else None
    anomaly_param = (
        True if anomaly_filter == "Anomaly Only"
        else False if anomaly_filter == "Normal Only"
        else None
    )

    events_data, error = get_events(
        per_page=per_page,
        severity=severity_param,
        is_anomaly=anomaly_param,
    )

    if error:
        st.error(f"Error loading events: {error}")
    elif events_data and events_data.get("events"):
        total = events_data.get("total", 0)
        st.caption(f"Showing {len(events_data['events'])} of {total:,} total events")

        df_events = pd.DataFrame(events_data["events"])
        display_cols = [
            "id", "timestamp", "source_ip", "dest_ip", "protocol",
            "severity", "is_anomaly", "anomaly_score", "rf_probability",
            "failed_logins", "bytes_out", "unusual_hour", "port_number",
            "alert_reason"
        ]
        display_cols = [c for c in display_cols if c in df_events.columns]
        df_display = df_events[display_cols].copy()

        if "timestamp" in df_display.columns:
            df_display["timestamp"] = pd.to_datetime(df_display["timestamp"]).dt.strftime("%Y-%m-%d %H:%M")
        if "anomaly_score" in df_display.columns:
            df_display["anomaly_score"] = df_display["anomaly_score"].apply(
                lambda x: f"{x:.4f}" if x is not None else "N/A"
            )
        if "rf_probability" in df_display.columns:
            df_display["rf_probability"] = df_display["rf_probability"].apply(
                lambda x: f"{x:.3f}" if x is not None else "N/A"
            )

        st.dataframe(df_display, use_container_width=True, hide_index=True)

        # Event detail viewer
        st.subheader("Event Detail View")
        event_id = st.number_input("Enter Event ID to inspect", min_value=1, step=1)
        if st.button("🔎 View Event Detail"):
            try:
                r = requests.get(f"{API_V1}/events/{event_id}", timeout=5)
                if r.status_code == 200:
                    event = r.json()
                    col_d1, col_d2 = st.columns(2)
                    with col_d1:
                        st.markdown(f"**Event ID:** {event['event_id']}")
                        st.markdown(f"**Timestamp:** {event['timestamp']}")
                        st.markdown(f"**Source IP:** {event.get('source_ip', 'N/A')}")
                        st.markdown(f"**Dest IP:** {event.get('dest_ip', 'N/A')}")
                        st.markdown(f"**Protocol:** {event.get('protocol', 'N/A')}")
                        st.markdown(f"**Port:** {event.get('port_number', 'N/A')}")
                    with col_d2:
                        sev = event.get("severity", "Normal")
                        sev_class = f"severity-{sev.lower()}"
                        st.markdown(
                            f"**Severity:** <span class='{sev_class}'>{sev}</span>",
                            unsafe_allow_html=True
                        )
                        st.markdown(f"**Is Anomaly:** {'⚠️ Yes' if event['is_anomaly'] else '✅ No'}")
                        score = event.get("anomaly_score")
                        st.markdown(f"**IF Score:** {score:.4f if score is not None else 'N/A'}")
                        rf_prob = event.get("rf_probability")
                        st.markdown(f"**RF Probability:** {rf_prob:.3f if rf_prob is not None else 'N/A'}")
                        st.markdown(f"**Model:** {event.get('prediction_source', 'N/A')}")

                    st.markdown("**Alert Reason:**")
                    st.info(event.get("alert_reason", "No explanation available."))

                    st.markdown("""
                    <div class="info-box">
                    <strong>📝 Score Interpretation Note</strong><br>
                    The <em>anomaly_score</em> is a raw IsolationForest output — a relative measure, 
                    not a calibrated probability. Scores below 0 indicate anomalous patterns compared 
                    to the training baseline. The alert_reason above is rule-based, not a direct model explanation.
                    </div>
                    """, unsafe_allow_html=True)
                elif r.status_code == 404:
                    st.error(f"Event {event_id} not found.")
                else:
                    st.error(f"Error: {r.status_code}")
            except Exception as e:
                st.error(f"Error fetching event: {e}")

        # CSV export
        st.divider()
        csv_export = df_events.to_csv(index=False).encode()
        st.download_button(
            "📥 Export Events to CSV",
            data=csv_export,
            file_name=f"events_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )
    else:
        st.info("No events found matching your filters. Try uploading a dataset first.")


# ═══════════════════════════════════════════════════════════════
# PAGE 4: Model Training
# ═══════════════════════════════════════════════════════════════

elif page == "🤖 Model Training":
    st.title("🤖 Model Training & Evaluation")

    # Current model metrics
    st.subheader("Current Model Status")
    metrics, error = get_model_metrics()

    if error:
        st.warning(f"⚠️ {error}")
        st.markdown("""
        **To train a model:**
        ```powershell
        python scripts/generate_sample_data.py
        python scripts/train_model.py
        ```
        Or use the API endpoint below.
        """)
    else:
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Model Type", metrics.get("model_type", "N/A").replace("_", " ").title())
        with m2:
            st.metric("Training Rows", f"{metrics.get('training_rows', 0):,}")
        with m3:
            trained_at = metrics.get("trained_at", "N/A")
            if trained_at and trained_at != "N/A":
                try:
                    dt = datetime.fromisoformat(trained_at.replace("Z", "+00:00"))
                    trained_at = dt.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    pass
            st.metric("Trained At", trained_at)
        with m4:
            st.metric("Has Labels", "Yes" if metrics.get("has_labels") else "No")

        # Supervised metrics (only if labels were available)
        if metrics.get("f1_score") is not None:
            st.subheader("Supervised Metrics (RandomForest on test set)")

            with st.expander("ℹ️ Understanding These Metrics", expanded=False):
                st.markdown("""
                **Important disclaimer:** These metrics are computed on the **synthetic test set only**.
                They measure how well the RandomForest learned to classify the synthetic anomaly patterns.
                
                - **Precision:** Of all events flagged as threats, what fraction were actual threats?
                - **Recall:** Of all actual threats, what fraction did the model detect?
                - **F1 Score:** Harmonic mean of precision and recall (balance of both)
                - **Accuracy:** Overall correct predictions / total predictions
                
                ⚠️ These numbers do NOT reflect real-world performance on actual financial network traffic.
                """)

            col_m1, col_m2, col_m3, col_m4 = st.columns(4)
            col_m1.metric("Precision", f"{metrics.get('precision', 0):.4f}")
            col_m2.metric("Recall", f"{metrics.get('recall', 0):.4f}")
            col_m3.metric("F1 Score", f"{metrics.get('f1_score', 0):.4f}")
            col_m4.metric("Accuracy", f"{metrics.get('accuracy', 0):.4f}")

            # Gauge chart for F1
            f1 = metrics.get("f1_score", 0)
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=f1 * 100,
                title={"text": "F1 Score (%)", "font": {"color": "#e2e8f0"}},
                gauge={
                    "axis": {"range": [0, 100], "tickcolor": "#64748b"},
                    "bar": {"color": "#3b82f6"},
                    "steps": [
                        {"range": [0, 60], "color": "#1e293b"},
                        {"range": [60, 80], "color": "#1e3a5f"},
                        {"range": [80, 100], "color": "#1e4d2b"},
                    ],
                    "threshold": {
                        "line": {"color": "#22c55e", "width": 4},
                        "value": 80,
                    },
                },
                number={"font": {"color": "#e2e8f0"}, "suffix": "%"},
            ))
            fig_gauge.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e2e8f0"),
                height=250,
                margin=dict(t=30, b=20),
            )
            st.plotly_chart(fig_gauge, use_container_width=True)
        else:
            st.info("No supervised metrics available — dataset had no labels. Only IsolationForest was trained.")
            if metrics.get("if_anomaly_count") is not None:
                col_if1, col_if2 = st.columns(2)
                col_if1.metric("IF Anomalies", metrics.get("if_anomaly_count"))
                col_if2.metric("IF Normal", metrics.get("if_normal_count"))

        # Model notes
        if metrics.get("notes"):
            st.caption(f"Notes: {metrics['notes']}")

    st.divider()

    # Train via API
    st.subheader("🚀 Trigger Model Training")
    st.info("Prerequisites: Run `python scripts/generate_sample_data.py` first to create the sample dataset.")

    if st.button("🔄 Train Model (via API)", type="primary"):
        with st.spinner("Training... this takes 20-60 seconds depending on your machine."):
            try:
                r = requests.post(f"{API_V1}/model/train", timeout=120)
                if r.status_code == 202:
                    result = r.json()
                    clear_cache()
                    st.success("✅ Model trained successfully!")
                    if result.get("metrics", {}).get("f1_score"):
                        f1 = result["metrics"]["f1_score"]
                        st.metric("F1 Score", f"{f1:.4f}")
                elif r.status_code == 404:
                    st.error(r.json().get("detail", "Sample data not found."))
                    st.code("python scripts/generate_sample_data.py", language="bash")
                else:
                    st.error(f"Training failed: {r.json().get('detail', r.text)}")
            except requests.exceptions.ConnectionError:
                st.error("API not running. Start with: `uvicorn app.main:app --reload --port 8000`")
            except Exception as e:
                st.error(f"Error: {e}")


# ═══════════════════════════════════════════════════════════════
# PAGE 5: API Documentation
# ═══════════════════════════════════════════════════════════════

elif page == "📖 API Documentation":
    st.title("📖 API Reference & Project Info")

    st.markdown("""
    <div class="info-box">
    The <strong>interactive API documentation</strong> (Swagger UI) is available at:
    <a href="http://localhost:8000/docs" target="_blank" style="color: #60a5fa;">
        http://localhost:8000/docs
    </a><br>
    ReDoc alternative: 
    <a href="http://localhost:8000/redoc" target="_blank" style="color: #60a5fa;">
        http://localhost:8000/redoc
    </a>
    </div>
    """, unsafe_allow_html=True)

    tab_api, tab_arch, tab_setup = st.tabs(["API Endpoints", "Architecture", "Setup Commands"])

    with tab_api:
        endpoints = [
            ("GET", "/health", "Application health check. Returns DB status, model status, event count."),
            ("GET", "/", "API information and endpoint list."),
            ("GET", "/api/v1/summary", "Dashboard KPI statistics from database."),
            ("POST", "/api/v1/analyze", "Analyze 1-1000 events (JSON body). Returns predictions."),
            ("POST", "/api/v1/analyze/csv", "Upload and analyze a CSV file (multipart)."),
            ("GET", "/api/v1/events", "List detection events with pagination and filtering."),
            ("GET", "/api/v1/events/{id}", "Get one detection event by integer ID."),
            ("GET", "/api/v1/model/metrics", "Get latest model evaluation metrics."),
            ("POST", "/api/v1/model/train", "Trigger model training (uses sample dataset)."),
        ]

        for method, path, desc in endpoints:
            color = {"GET": "#22c55e", "POST": "#3b82f6"}.get(method, "#94a3b8")
            st.markdown(
                f'<span style="background:{color}; color: #0f172a; padding: 2px 8px; '
                f'border-radius: 4px; font-weight: 700; font-size: 0.75rem; font-family: monospace;">'
                f'{method}</span> '
                f'<code style="color: #e2e8f0; font-size: 0.95rem;">{path}</code> — {desc}',
                unsafe_allow_html=True
            )

        st.divider()
        st.subheader("Example: POST /api/v1/analyze")
        st.code("""
POST http://localhost:8000/api/v1/analyze
Content-Type: application/json

{
  "events": [
    {
      "source_ip": "192.0.2.10",
      "dest_ip": "198.51.100.5",
      "protocol": "SSH",
      "failed_logins": 25,
      "bytes_in": 1024.0,
      "bytes_out": 512.0,
      "connection_duration": 45.5,
      "unusual_hour": true,
      "port_number": 22
    }
  ]
}
        """, language="json")

    with tab_arch:
        st.markdown("""
        ## System Architecture

        ```
        CSV Upload / API Events
               ↓
        Data Validation (ingestion.py)
               ↓
        Feature Preprocessing (preprocessing.py)
        [Imputation → Scaling → Encoding]
               ↓
        ML Pipeline (detection.py)
        ├── IsolationForest (always)
        └── RandomForest (if labels available)
               ↓
        Severity Assignment (rule-based layer)
        [High / Suspicious / Normal]
               ↓
        Alert Explanation (rule-based)
               ↓
        SQLite Persistence (database.py)
        [DetectionEvent / DatasetImport / ModelRun]
               ↓
        FastAPI REST API (main.py)
               ↓
        Streamlit Dashboard (streamlit_app.py)
        ```

        ## Database Schema
        - **DetectionEvent** — Primary output: each analyzed event with its prediction
        - **DatasetImport** — Tracks each CSV upload/ingestion session
        - **ModelRun** — Records each training session with metrics and config

        ## ML Models
        - **IsolationForest**: Unsupervised anomaly detection. No labels needed.
          Trained on all data; anomalous events are isolated in fewer random partitions.
        - **RandomForest**: Supervised classifier. Trained only when `label` column exists.
          Provides calibrated class probabilities for better interpretability.
        """)

    with tab_setup:
        st.markdown("""
        ## Quick Start (PowerShell)

        ```powershell
        # 1. Create and activate virtual environment
        python -m venv venv
        .\\venv\\Scripts\\Activate.ps1

        # 2. Install dependencies
        pip install -r requirements.txt

        # 3. Generate sample data (SYNTHETIC)
        python scripts/generate_sample_data.py

        # 4. Initialize database and seed demo data
        python scripts/initialize_db.py

        # 5. Train the ML models
        python scripts/train_model.py

        # 6. Start the FastAPI backend
        uvicorn app.main:app --reload --port 8000

        # 7. In a new terminal, start the Streamlit dashboard
        streamlit run app/dashboard/streamlit_app.py

        # 8. Run tests
        pytest tests/ -v
        ```

        ## URLs
        - **Dashboard**: http://localhost:8501
        - **API Docs**: http://localhost:8000/docs
        - **ReDoc**: http://localhost:8000/redoc
        - **Health**: http://localhost:8000/health
        """)
