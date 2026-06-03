"""
dashboard/components/sidebar.py — Reusable EDR Sidebar Panel
==============================================================
Defines the unified Cyberpunk dark SOC navigation sidebar,
active threat KPIs, risk indices, and platform health status badges.
"""

import streamlit as st
import datetime
import platform

from core.risk_scoring import calculate_risk_score

def render_sidebar():
    """Render consistent custom styled EDR sidebar and EDR dashboard metrics."""
    with st.sidebar:
        # Header Box
        st.markdown("""
        <div style="text-align:center;padding:10px 0 18px">
          <div style="font-family:'Syne',sans-serif;font-size:1.4rem;font-weight:900;
               color:#00D4FF!important;letter-spacing:.25em;text-shadow:0 0 20px rgba(0,212,255,.45)">DFIR</div>
          <div style="font-family:'Share Tech Mono',monospace;font-size:.56rem;
               color:#2D6A9F!important;letter-spacing:.32em;margin-top:4px">SENTINEL ENTERPRISE</div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("<hr style='margin:10px 0;border-color:#0E2845'>", unsafe_allow_html=True)
        
        # Real-time KPIs from Database
        stats = calculate_risk_score()
        score = stats["risk_score"]
        level = stats["risk_level"]
        color = stats["risk_color"]
        
        st.markdown(f"""
        <div style="background:linear-gradient(135deg,rgba(10,31,53,.8),rgba(6,21,37,.8));
                    border:1px solid #1A3A5C;border-radius:8px;padding:12px 14px;margin-bottom:14px">
          <div style="font-family:'Share Tech Mono',monospace;font-size:.55rem;letter-spacing:.2em;color:#2D6A9F!important;margin-bottom:6px">EXPOSURE LEVEL</div>
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="font-family:'Syne',sans-serif;font-size:1.8rem;font-weight:900;color:{color}!important;text-shadow:0 0 15px {color}">{score}</span>
            <span style="font-family:'Share Tech Mono',monospace;font-size:.65rem;font-weight:700;color:{color}!important;border:1px solid {color};padding:2px 6px;border-radius:4px">{level}</span>
          </div>
          <div style="background:#0E2845;border-radius:2px;height:4px;margin-top:8px;overflow:hidden">
            <div style="height:100%;width:{score}%;background:{color};box-shadow:0 0 6px {color}"></div>
          </div>
        </div>
        """, unsafe_allow_html=True)
        
        # Operational Stats Box
        st.markdown(f"""
        <div style="background:rgba(2,12,24,.6);border:1px solid #0E2845;border-radius:8px;padding:12px 14px;font-family:'Share Tech Mono',monospace;font-size:.6rem">
          <div style="display:flex;justify-content:space-between;margin-bottom:6px">
            <span style="color:#2D6A9F!important">Total Events</span>
            <span style="font-weight:700">{stats['total_events']}</span>
          </div>
          <div style="display:flex;justify-content:space-between;margin-bottom:6px">
            <span style="color:#2D6A9F!important">Active Alerts</span>
            <span style="font-weight:700;color:#FF2D55!important">{stats['active_alerts']}</span>
          </div>
          <div style="display:flex;justify-content:space-between;margin-bottom:6px">
            <span style="color:#2D6A9F!important">Open Cases</span>
            <span style="font-weight:700;color:#FF9500!important">{stats['active_incidents']}</span>
          </div>
          <div style="display:flex;justify-content:space-between">
            <span style="color:#2D6A9F!important">Platform OS</span>
            <span style="font-weight:700">{platform.system()}</span>
          </div>
        </div>
        """, unsafe_allow_html=True)
        
        st.markdown("<hr style='margin:14px 0;border-color:#0E2845'>", unsafe_allow_html=True)

        # Health dot & Platform Info
        now = datetime.datetime.utcnow().strftime("%H:%M:%S")
        st.markdown(f"""
        <div style="text-align:center;font-family:'Share Tech Mono',monospace;font-size:.56rem;color:#2D6A9F!important">
          <span style="display:inline-block;width:6px;height:6px;background:#30D158;border-radius:50%;box-shadow:0 0 8px #30D158;margin-right:6px;animation:blink 1.5s ease-in-out infinite"></span>
          EDR AGENTS: ACTIVE &middot; {now} UTC
        </div>
        """, unsafe_allow_html=True)

def apply_global_styles():
    """Apply global Cyberpunk SOC styles and fonts to the active streamlit page."""
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Syne:wght@700;900&family=Inter:wght@400;500&display=swap');
    :root {
      --bg:#020C18;--bg2:#061525;--bg3:#0A1F35;--bg4:#0E2845;
      --c:#00D4FF;--a:#FF9500;--r:#FF2D55;--g:#30D158;--p:#BF5AF2;--y:#FFD60A;
      --t1:#E8F4FD;--t2:#7BAFD4;--t3:#2D6A9F;--bd:#0E2845;--bd2:#1A3A5C;
      --mono:'Share Tech Mono',monospace;--hd:'Syne',sans-serif;
    }
    .stApp {
      background: var(--bg)!important;
      background-image: radial-gradient(ellipse 80% 50% at 50% -20%, rgba(0,100,180,.12), transparent)!important;
    }
    .stApp * {
      color: var(--t1)!important;
    }
    [data-testid="stSidebar"] {
      background: linear-gradient(180deg, var(--bg2), var(--bg))!important;
      border-right: 1px solid var(--bd2)!important;
    }
    #MainMenu, footer, header {
      visibility: hidden;
    }
    .block-container {
      padding: 0.5rem 1.5rem 2rem!important;
      max-width: 100%!important;
    }
    .stApp::after {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      z-index: 9999;
      background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,212,255,.005) 2px, rgba(0,212,255,.005) 3px);
    }
    
    /* Header styling */
    .hdr {
      background: linear-gradient(135deg, rgba(6,21,37,.95), rgba(10,31,53,.95));
      border: 1px solid var(--bd2);
      border-top: 2px solid var(--c);
      border-radius: 10px;
      padding: 16px 24px;
      margin-bottom: 20px;
      position: relative;
      overflow: hidden;
    }
    .htitle {
      font-family: var(--hd);
      font-size: 1.8rem;
      font-weight: 900;
      color: var(--c)!important;
      text-shadow: 0 0 25px rgba(0,212,255,.35);
      letter-spacing: .08em;
      margin: 0;
      line-height: 1.1;
    }
    .hsub {
      font-family: var(--mono);
      font-size: .58rem;
      color: var(--t3)!important;
      letter-spacing: .28em;
      margin-top: 4px;
    }
    
    /* Reusable sections headers */
    .sh {
      font-family: var(--mono);
      font-size: .6rem;
      letter-spacing: .25em;
      color: var(--t3)!important;
      text-transform: uppercase;
      border-bottom: 1px solid var(--bd2);
      padding-bottom: 6px;
      margin: 18px 0 12px;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .sh::before {
      content: "";
      width: 3px;
      height: 12px;
      background: var(--c);
      border-radius: 2px;
      box-shadow: 0 0 6px var(--c);
    }
    
    /* Buttons customization */
    .stButton>button {
      background: transparent!important;
      color: var(--c)!important;
      border: 1px solid var(--bd2)!important;
      border-radius: 6px!important;
      font-family: var(--mono)!important;
      font-size: .67rem!important;
      letter-spacing: .08em!important;
      transition: all .2s!important;
      width: 100%;
    }
    .stButton>button:hover {
      border-color: var(--c)!important;
      background: rgba(0,212,255,.08)!important;
      box-shadow: 0 0 12px rgba(0,212,255,.15)!important;
    }
    
    /* Streamlit overrides */
    [data-testid="stDataFrame"] {
      background: var(--bg3)!important;
      border: 1px solid var(--bd2)!important;
      border-radius: 8px!important;
    }
    .stTabs [data-baseweb="tab-list"] {
      background: var(--bg2);
      border-bottom: 1px solid var(--bd2);
    }
    .stTabs [data-baseweb="tab"] {
      font-family: var(--mono);
      font-size: .65rem;
      color: var(--t3)!important;
    }
    .stTabs [aria-selected="true"] {
      color: var(--c)!important;
      border-bottom: 2px solid var(--c)!important;
    }
    [data-testid="stMetric"] {
      background: var(--bg3);
      border: 1px solid var(--bd2);
      border-radius: 8px;
      padding: 10px 14px!important;
    }
    [data-testid="stMetricLabel"] {
      font-family: var(--mono)!important;
      font-size: .55rem!important;
      letter-spacing: .15em!important;
      color: var(--t3)!important;
      text-transform: uppercase;
    }
    [data-testid="stMetricValue"] {
      font-family: var(--hd)!important;
      font-size: 1.5rem!important;
      font-weight: 900!important;
    }
    </style>
    """, unsafe_allow_html=True)
