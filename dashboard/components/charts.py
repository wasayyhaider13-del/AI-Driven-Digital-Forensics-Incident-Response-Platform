"""
dashboard/components/charts.py — Reusable Plotly SOC Chart Components
======================================================================
Defines high-fidelity Plotly charts: Sankey Diagrams for attack flows,
heatmaps for temporal analysis, and gauge charts for EDR risk scoring.
"""

import pandas as pd
import plotly.graph_objects as go
from typing import List, Dict, Any

# Plotly styling templates
PL = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
          font=dict(family="Share Tech Mono", color="#7BAFD4", size=11),
          margin=dict(l=10, r=10, t=30, b=10))
GRD = dict(gridcolor="#0E2845", linecolor="#0E2845", zerolinecolor="#0E2845")

def render_risk_gauge(score: int, color: str, label: str = "RISK INDEX") -> go.Figure:
    """Renders a premium circular risk exposure gauge indicator."""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        title={'text': label, 'font': {'size': 12, 'family': 'Share Tech Mono', 'color': '#7BAFD4'}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#0E2845"},
            'bar': {'color': color},
            'bgcolor': "rgba(10,31,53,.3)",
            'borderwidth': 1,
            'bordercolor': "#1A3A5C",
            'steps': [
                {'range': [0, 25], 'color': 'rgba(48,209,88,.05)'},
                {'range': [25, 50], 'color': 'rgba(255,214,10,.05)'},
                {'range': [50, 75], 'color': 'rgba(255,149,0,.05)'},
                {'range': [75, 100], 'color': 'rgba(255,45,85,.05)'}
            ],
            'threshold': {
                'line': {'color': "#FF2D55", 'width': 3},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    fig.update_layout(**PL, height=180) # type: ignore
    return fig

def render_sankey_diagram(events: List[Dict[str, Any]]) -> go.Figure:
    """
    Renders an interactive Sankey Diagram mapping the EDR attack pipeline:
    Source Endpoint -> Matched Signature Rule -> Triggered Severity -> Classification Target
    """
    if not events:
        # Default mock sankey nodes if list is empty
        source_labels = ["Browser", "Network", "Process", "Memory"]
        rule_labels = ["KEYWORD_MATCH", "BEACONING_TCP", "LOLBIN_CERTUTIL", "YARA_SLIVER"]
        sev_labels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        target_labels = ["BENIGN", "SUSPICIOUS", "MALICIOUS"]
    else:
        # Generate dynamically based on events list
        source_labels = list(set(e.get("event_type", "System") for e in events))
        rule_labels = list(set(e.get("matched_rule", "NONE") for e in events))
        sev_labels = list(set(e.get("severity", "LOW") for e in events))
        target_labels = list(set(e.get("llm", {}).get("classification", "UNKNOWN") for e in events))

    all_labels = source_labels + rule_labels + sev_labels + target_labels
    label_map = {lbl: i for i, lbl in enumerate(all_labels)}

    sources = []
    targets = []
    values = []

    # Map Event Type -> Matched Rule
    type_rule_pairs = {}
    for e in events:
        src = e.get("event_type", "System")
        tgt = e.get("matched_rule", "NONE")
        key = (src, tgt)
        type_rule_pairs[key] = type_rule_pairs.get(key, 0) + 1
        
    for (src, tgt), val in type_rule_pairs.items():
        sources.append(label_map[src])
        targets.append(label_map[tgt])
        values.append(val)

    # Map Matched Rule -> Severity
    rule_sev_pairs = {}
    for e in events:
        src = e.get("matched_rule", "NONE")
        tgt = e.get("severity", "LOW")
        key = (src, tgt)
        rule_sev_pairs[key] = rule_sev_pairs.get(key, 0) + 1

    for (src, tgt), val in rule_sev_pairs.items():
        sources.append(label_map[src])
        targets.append(label_map[tgt])
        values.append(val)

    # Map Severity -> Classification
    sev_class_pairs = {}
    for e in events:
        src = e.get("severity", "LOW")
        tgt = e.get("llm", {}).get("classification", "UNKNOWN")
        key = (src, tgt)
        sev_class_pairs[key] = sev_class_pairs.get(key, 0) + 1

    for (src, tgt), val in sev_class_pairs.items():
        sources.append(label_map[src])
        targets.append(label_map[tgt])
        values.append(val)

    # If maps are completely empty, supply baseline values
    if not values:
        sources = [0, 1, 2, 3, 4, 5, 6, 7]
        targets = [4, 5, 6, 7, 8, 9, 10, 10]
        values = [5, 10, 3, 2, 5, 10, 3, 2]

    # Render Plotly Sankey
    fig = go.Figure(data=[go.Sankey(
        node=dict(
            pad=15,
            thickness=15,
            line=dict(color="#1A3A5C", width=1),
            label=all_labels,
            color=["#00D4FF", "#BF5AF2", "#30D158", "#FFD60A", "#FF9500", "#FF2D55"] * 3
        ),
        link=dict(
            source=sources,
            target=targets,
            value=values,
            color="rgba(0,212,255,.08)"
        )
    )])
    
    fig.update_layout(**PL, title_text="EDR ATTACK PIPELINE FLOW", title_font=dict(size=12, family="Syne"), height=300) # type: ignore
    return fig

def render_threat_heatmap(df: pd.DataFrame) -> go.Figure:
    """Renders Plotly temporal analysis heatmaps based on threat activity times."""
    fig = go.Figure()
    if df.empty:
        # Empty placeholder
        fig.update_layout(**PL, height=200) # type: ignore
        return fig

    df = df.copy()
    df["dt"] = pd.to_datetime(df["visit_time"], errors="coerce")
    df["hr"] = df["dt"].dt.hour
    df["day"] = df["dt"].dt.strftime("%a %m/%d")
    
    pivot = df.pivot_table(index="day", columns="hr", values="threat_score", aggfunc="mean").fillna(0)
    if not pivot.empty:
        fig.add_trace(go.Highlight(z=pivot.values, x=pivot.columns.tolist(), y=pivot.index.tolist()) if hasattr(go, "Highlight") else go.Heatmap(
            z=pivot.values, x=pivot.columns.tolist(), y=pivot.index.tolist(),
            colorscale=[[0, "#020C18"], [.3, "#0E2845"], [.6, "#00D4FF"], [.8, "#FF9500"], [1, "#FF2D55"]],
            hovertemplate="Hour %{x}:00 | %{y}<br>Avg Score: %{z:.0f}<extra></extra>",
            showscale=True, colorbar=dict(thickness=10, tickfont=dict(size=8))
        ))
        fig.update_layout(**PL, height=200, xaxis_title="Hour of Day (UTC)") # type: ignore
        fig.update_layout(xaxis=dict(**GRD, tickmode="linear", dtick=2), yaxis=dict(**GRD))
    return fig
