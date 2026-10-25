"""
CyberShield AI — Intelligent Phishing and URL Threat Detection System
Streamlit Dashboard Application
"""

import datetime
import io
import json
import os
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go

from detector.url_analyzer import URLAnalyzer, analyze_url
from detector.email_analyzer import EmailAnalyzer, analyze_email_message
from detector.risk_scorer import RiskScorer, evaluate_risk
from detector.ml_engine import PhishingMLClassifier, get_benchmark_metrics

# Streamlit Page Configuration
st.set_page_config(
    page_title="CyberShield AI — Phishing & Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Dark Navy & Teal Styling
st.markdown("""
<style>
    /* Dark navy theme background */
    .stApp {
        background-color: #080d1a;
        color: #e2e8f0;
    }
    
    /* Top banner card */
    .cyber-header {
        background: linear-gradient(135deg, #0b132b 0%, #1c2541 100%);
        border: 1px solid #1e3a8a;
        border-radius: 12px;
        padding: 24px;
        margin-bottom: 24px;
    }
    
    /* Stat KPI card */
    .metric-card {
        background-color: #0f172a;
        border: 1px solid #1e293b;
        border-radius: 10px;
        padding: 16px;
        text-align: center;
    }
    .metric-value {
        font-family: 'JetBrains Mono', monospace;
        font-size: 28px;
        font-weight: 700;
        color: #38bdf8;
    }
    .metric-label {
        font-size: 13px;
        color: #94a3b8;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    
    /* Risk Badge */
    .risk-badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 14px;
    }
    
    /* Recommendation item */
    .rec-item {
        background-color: #0b1528;
        border-left: 3px solid #06b6d4;
        padding: 10px 14px;
        margin-bottom: 8px;
        border-radius: 0 6px 6px 0;
        font-size: 14px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize Session State
if "history" not in st.session_state:
    st.session_state.history = []

url_analyzer = URLAnalyzer()
email_analyzer = EmailAnalyzer()
risk_scorer = RiskScorer()
ml_classifier = PhishingMLClassifier()

# Sidebar Navigation
st.sidebar.markdown("### 🛡️ CyberShield AI")
st.sidebar.caption("Defensive Cyber Threat Analysis System")
st.sidebar.markdown("---")

nav_choice = st.sidebar.radio(
    "Navigation",
    [
        "Threat Dashboard",
        "URL Threat Scanner",
        "Email / Message Scanner",
        "ML Engine & Evaluation",
        "Scan History & Export",
        "System Documentation"
    ]
)

st.sidebar.markdown("---")
st.sidebar.caption("Version: 1.0.0 (Academic Portfolio Edition)")
st.sidebar.caption("Mode: Strict Defensive (Offline Static Inspection)")

# ---------------------------------------------------------
# VIEW 1: THREAT DASHBOARD
# ---------------------------------------------------------
if nav_choice == "Threat Dashboard":
    st.markdown("""
    <div class="cyber-header">
        <h1 style="color: #38bdf8; margin: 0; font-size: 32px;">🛡️ CyberShield AI Threat Dashboard</h1>
        <p style="color: #94a3b8; margin-top: 8px; font-size: 15px;">
            Intelligent heuristic and machine-learning threat detection for suspicious URLs and social-engineering messages.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # Calculate real-time stats
    total_scans = len(st.session_state.history)
    high_critical = sum(1 for h in st.session_state.history if h.get("tier") in ["High Risk", "Critical Risk"])
    url_scans = sum(1 for h in st.session_state.history if h.get("type") == "URL")
    email_scans = sum(1 for h in st.session_state.history if h.get("type") == "Email/Message")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value">{total_scans}</div>
            <div class="metric-label">Total Scans Performed</div>
        </div>
        """, unsafe_allow_html=True)
    with col2:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #ef4444;">{high_critical}</div>
            <div class="metric-label">High / Critical Flags</div>
        </div>
        """, unsafe_allow_html=True)
    with col3:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #10b981;">{url_scans}</div>
            <div class="metric-label">URLs Inspected</div>
        </div>
        """, unsafe_allow_html=True)
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="color: #a855f7;">{email_scans}</div>
            <div class="metric-label">Messages Inspected</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    col_chart1, col_chart2 = st.columns([1, 1])

    with col_chart1:
        st.subheader("Risk Distribution of Session Scans")
        if total_scans > 0:
            tier_counts = {"Low Risk": 0, "Medium Risk": 0, "High Risk": 0, "Critical Risk": 0}
            for h in st.session_state.history:
                tier = h.get("tier", "Low Risk")
                tier_counts[tier] = tier_counts.get(tier, 0) + 1
            
            fig = px.pie(
                values=list(tier_counts.values()),
                names=list(tier_counts.keys()),
                color=list(tier_counts.keys()),
                color_discrete_map={
                    "Low Risk": "#10b981",
                    "Medium Risk": "#f59e0b",
                    "High Risk": "#ef4444",
                    "Critical Risk": "#dc2626"
                },
                hole=0.4
            )
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font_color="#e2e8f0",
                margin=dict(t=20, b=20, l=20, r=20)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No scan history recorded in current session yet. Run a scan in the URL or Email Scanner tab.")

    with col_chart2:
        st.subheader("Core Defensive Capabilities")
        st.markdown("""
        - **Static Lexical Extraction**: URL length, character distribution, raw IP detection, and Shannon entropy.
        - **Social Engineering Detection**: Urgency timers, credential solicitation, fear-based coercion, and reward lures.
        - **Machine Learning Integration**: Calibrated probability estimation using supervised decision boundaries.
        - **Defensive Safety Protocol**: Strictly non-intrusive. Zero live DNS probing, zero HTTP payload requests, zero malware download.
        - **Transparent Explainability**: Every score links directly to specific detected indicators and defensive actions.
        """)

# ---------------------------------------------------------
# VIEW 2: URL THREAT SCANNER
# ---------------------------------------------------------
elif nav_choice == "URL Threat Scanner":
    st.markdown("## 🔍 URL Threat Analyzer")
    st.caption("Inspect suspicious links statically without visiting destination servers.")

    # Demo prefill buttons
    st.markdown("**Simulated Test Cases (Safe Demo Links):**")
    dcol1, dcol2, dcol3 = st.columns(3)
    demo_url = ""
    if dcol1.button("🟢 Legitimate Official Portal"):
        demo_url = "https://www.cisa.gov/resources-tools/cybersecurity-alerts"
    if dcol2.button("🟡 URL Shortener Link"):
        demo_url = "https://bit.ly/secure-banking-verification-notice"
    if dcol3.button("🔴 Blatant IP Credential Lure"):
        demo_url = "http://user@192.168.1.100/paypal/login.php?verify=1"

    input_url = st.text_input("Enter URL to analyze:", value=demo_url, placeholder="e.g. http://192.168.1.50/account/login")

    if st.button("Scan URL", type="primary"):
        if not input_url.strip():
            st.warning("Please enter a URL to inspect.")
        else:
            with st.spinner("Extracting structural features and evaluating risk..."):
                analysis = url_analyzer.extract_features(input_url)
                if not analysis.get("valid"):
                    st.error(f"Error parsing URL: {analysis.get('error')}")
                else:
                    risk = risk_scorer.score_url(analysis)
                    ml_pred = ml_classifier.predict(analysis)

                    # Save to session history
                    st.session_state.history.append({
                        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "type": "URL",
                        "target": input_url[:60] + ("..." if len(input_url) > 60 else ""),
                        "score": risk["score"],
                        "tier": risk["tier"],
                        "ml_prediction": ml_pred["prediction"],
                        "ml_prob": ml_pred["phishing_percentage"]
                    })

                    # Display Result Cards
                    st.markdown("---")
                    res_col1, res_col2 = st.columns([1, 1])

                    with res_col1:
                        st.markdown(f"### Heuristic Risk Score: **{risk['score']}/100**")
                        st.markdown(f"<span class='risk-badge' style='background-color: {risk['color']}22; color: {risk['color']}; border: 1px solid {risk['color']};'>{risk['tier']}</span>", unsafe_allow_html=True)
                        st.caption("Calculated from weighted structural and lexical rule heuristics.")

                        st.markdown("#### Detected Risk Signals")
                        if analysis["signals"]:
                            for s in analysis["signals"]:
                                st.markdown(f"- **[{s['severity']}] {s['type']}**: {s['description']}")
                        else:
                            st.success("No critical threat signals detected in URL structure.")

                    with res_col2:
                        st.markdown(f"### ML Model Verdict: **{ml_pred['prediction']}**")
                        st.markdown(f"Confidence: **{ml_pred['confidence']}%** (Phishing probability: {ml_pred['phishing_percentage']}%)")
                        st.caption("Supervised Classifier trained on balanced lexical dataset.")

                        st.markdown("#### Actionable Defensive Recommendations")
                        for r in risk["recommendations"]:
                            st.markdown(f"<div class='rec-item'>{r}</div>", unsafe_allow_html=True)

                    # Structural Feature Table
                    st.markdown("---")
                    st.markdown("#### Extracted Lexical & Structural Metrics")
                    feat_df = pd.DataFrame([
                        {"Feature": "URL Length", "Value": analysis["url_length"], "Normal Baseline": "< 75 chars"},
                        {"Feature": "Dots Count", "Value": analysis["dot_count"], "Normal Baseline": "1-3"},
                        {"Feature": "Raw IP Host", "Value": "Yes" if analysis["is_ip"] else "No", "Normal Baseline": "No"},
                        {"Feature": "Uses HTTPS", "Value": "Yes" if analysis["uses_https"] else "No", "Normal Baseline": "Yes"},
                        {"Feature": "Known URL Shortener", "Value": "Yes" if analysis["is_shortener"] else "No", "Normal Baseline": "No"},
                        {"Feature": "Subdomain Count", "Value": analysis["subdomain_count"], "Normal Baseline": "0-1"},
                        {"Feature": "Domain Shannon Entropy", "Value": analysis["domain_entropy"], "Normal Baseline": "< 3.8"},
                        {"Feature": "Suspicious Keywords Found", "Value": ", ".join(analysis["matched_keywords"]) if analysis["matched_keywords"] else "None", "Normal Baseline": "None"},
                    ])
                    st.dataframe(feat_df, use_container_width=True)

# ---------------------------------------------------------
# VIEW 3: EMAIL / MESSAGE SCANNER
# ---------------------------------------------------------
elif nav_choice == "Email / Message Scanner":
    st.markdown("## ✉️ Email & Message Phishing Analyzer")
    st.caption("Detect social engineering tactics, urgency timers, credential solicitation, and dangerous links.")

    st.markdown("**Simulated Test Cases:**")
    mcol1, mcol2, mcol3 = st.columns(3)
    demo_email = ""
    if mcol1.button("🟢 Legitimate Meeting Invitation"):
        demo_email = "Hi Team, please find attached the agenda for tomorrow's security architecture review at 2 PM. Let me know if any topics need to be added."
    if mcol2.button("🟡 Unsolicited Prize Baiting"):
        demo_email = "Congratulations! You have won $1,000,000 in the international reward lottery! Claim your prize immediately by responding to this notice."
    if mcol3.button("🔴 Coercive Account Suspension"):
        demo_email = "URGENT ACTION REQUIRED: Your bank account will be suspended within 24 hours due to unauthorized activity. Verify your password and 2FA code immediately at http://192.168.1.50/bank/verify.php to prevent legal action."

    input_message = st.text_area("Paste email or message text here:", value=demo_email, height=160)

    if st.button("Scan Message", type="primary"):
        if not input_message.strip():
            st.warning("Please paste email or message text.")
        else:
            with st.spinner("Analyzing message body and extracting links..."):
                m_res = email_analyzer.analyze_message(input_message)
                m_risk = risk_scorer.score_email_message(m_res)

                st.session_state.history.append({
                    "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "type": "Email/Message",
                    "target": input_message[:50] + "...",
                    "score": m_risk["score"],
                    "tier": m_risk["tier"],
                    "ml_prediction": "N/A (Heuristic NLP)",
                    "ml_prob": "N/A"
                })

                st.markdown("---")
                col_m1, col_m2 = st.columns([1, 1])

                with col_m1:
                    st.markdown(f"### Threat Risk Score: **{m_risk['score']}/100**")
                    st.markdown(f"<span class='risk-badge' style='background-color: {m_risk['color']}22; color: {m_risk['color']}; border: 1px solid {m_risk['color']};'>{m_risk['tier']}</span>", unsafe_allow_html=True)
                    
                    st.markdown("#### Identified Social Engineering Signals")
                    if m_res["indicators"]:
                        for ind in m_res["indicators"]:
                            st.markdown(f"- **[{ind['severity']}] {ind['category']}**: {ind['explanation']} *(Trigger: '{ind['detected_term']}')*")
                    else:
                        st.success("No common social engineering triggers detected.")

                with col_m2:
                    st.markdown("#### Embedded Link Analysis")
                    if m_res["extracted_urls"]:
                        st.info(f"Found {len(m_res['extracted_urls'])} URL(s) in message body.")
                        for u_rep in m_res["url_analysis_reports"]:
                            u_eval = risk_scorer.score_url(u_rep)
                            st.markdown(f"- **`{u_rep['url']}`** → Score: **{u_eval['score']}/100** ({u_eval['tier']})")
                    else:
                        st.write("No embedded URLs identified in message body.")

                    st.markdown("#### Security Recommendations")
                    for r in m_risk["recommendations"]:
                        st.markdown(f"<div class='rec-item'>{r}</div>", unsafe_allow_html=True)

# ---------------------------------------------------------
# VIEW 4: ML ENGINE & EVALUATION
# ---------------------------------------------------------
elif nav_choice == "ML Engine & Evaluation":
    st.markdown("## 🧠 Machine Learning Engine & Validation")
    st.caption("Documented model architecture, evaluation metrics, and dataset governance.")

    metrics = get_benchmark_metrics()

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Accuracy", f"{metrics['accuracy']*100:.1f}%")
    m2.metric("Precision", f"{metrics['precision']*100:.1f}%")
    m3.metric("Recall", f"{metrics['recall']*100:.1f}%")
    m4.metric("F1-Score", f"{metrics['f1_score']*100:.1f}%")

    st.markdown("---")
    col_cm, col_imp = st.columns([1, 1])

    with col_cm:
        st.subheader("Confusion Matrix (Stratified Test Split)")
        cm_data = [
            [metrics["confusion_matrix"]["true_negatives"], metrics["confusion_matrix"]["false_positives"]],
            [metrics["confusion_matrix"]["false_negatives"], metrics["confusion_matrix"]["true_positives"]]
        ]
        fig_cm = px.imshow(
            cm_data,
            labels=dict(x="Predicted Class", y="Actual Class", color="Count"),
            x=["Legitimate", "Phishing"],
            y=["Legitimate", "Phishing"],
            text_auto=True,
            color_continuous_scale="Blues"
        )
        fig_cm.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="#e2e8f0")
        st.plotly_chart(fig_cm, use_container_width=True)

    with col_imp:
        st.subheader("Feature Importance Weights")
        feat_df = pd.DataFrame(metrics["feature_importances"])
        fig_bar = px.bar(
            feat_df,
            x="importance",
            y="feature",
            orientation="h",
            color="importance",
            color_continuous_scale="Teal",
            labels={"importance": "Gini Importance", "feature": "Feature"}
        )
        fig_bar.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font_color="#e2e8f0",
            yaxis=dict(autorange="reversed")
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    st.markdown("""
    ### ⚠️ Dataset Limitations & Academic Notice
    - **Dataset Provenance**: The dataset is a reproducible synthetic demonstration set engineered for academic validation. It must **not** be confused with enterprise real-world threat feeds (e.g. VirusTotal, PhishTank).
    - **Stratified Partitioning**: The 80/20 train/test split enforces class balance preservation to avoid optimistic bias.
    - **Data Leakage Prevention**: Feature extraction relies entirely on the URL string itself without querying external services or looking ahead into future telemetry.
    """)

# ---------------------------------------------------------
# VIEW 5: SCAN HISTORY & EXPORT
# ---------------------------------------------------------
elif nav_choice == "Scan History & Export":
    st.markdown("## 📜 Session Scan History")
    st.caption("Review all scans conducted in the current session and export audit logs.")

    if not st.session_state.history:
        st.info("No scans recorded yet. Analyze URLs or emails to populate this table.")
    else:
        df_hist = pd.DataFrame(st.session_state.history)
        st.dataframe(df_hist, use_container_width=True)

        col_csv, col_clear = st.columns([1, 1])
        with col_csv:
            csv_data = df_hist.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📥 Export History as CSV",
                data=csv_data,
                file_name="cybershield_scan_history.csv",
                mime="text/csv"
            )
        with col_clear:
            if st.button("🗑️ Clear Scan History"):
                st.session_state.history = []
                st.rerun()

# ---------------------------------------------------------
# VIEW 6: SYSTEM DOCUMENTATION
# ---------------------------------------------------------
elif nav_choice == "System Documentation":
    st.markdown("## 📖 System Architecture & Security Scope")
    st.markdown("""
    ### Defensive Security Scope
    CyberShield AI is engineered strictly for **defensive defensive threat identification and user education**:
    1. **Zero External Contact**: URLs are not queried via socket requests, DNS queries, or headless browsers.
    2. **Zero Credential Harvesting**: No user passwords or tokens are stored or transmitted.
    3. **Academic Integrity**: Clear distinction between rule heuristics and statistical machine learning inference.

    ### How Risk Scoring Works
    - **Low Risk (0–34)**: Baseline web structure, HTTPS enabled, standard domain hierarchy.
    - **Medium Risk (35–64)**: Presence of shorteners, minor lexical anomalies, or generic greeting.
    - **High Risk (65–84)**: Coercive urgency language, suspicious TLD, multiple threat keywords.
    - **Critical Risk (85–100)**: Direct IP host address, credential solicitation, userinfo obfuscation (@).
    """)
