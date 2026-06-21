"""Plotly SOC charts: Sankey attack pipeline, heatmaps, gauges."""

import pandas as pd
import plotly.graph_objects as go
from typing import List, Dict, Any

PL = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Share Tech Mono", color="#7BAFD4", size=11),
    margin=dict(l=10, r=10, t=30, b=10),
)
GRD = dict(gridcolor="#0E2845", linecolor="#0E2845", zerolinecolor="#0E2845")


def _event_source(event: Dict[str, Any]) -> str:
    return event.get("event_type") or event.get("source") or "Browser"


def render_sankey_diagram(events: List[Dict[str, Any]]) -> go.Figure:
    """Sankey: event source -> matched rule -> severity -> AI classification."""
    if not events:
        fig = go.Figure()
        fig.update_layout(**PL, height=200, title_text="No events to map")
        return fig

    source_labels = sorted(set(_event_source(e) for e in events))
    rule_labels = sorted(set(e.get("matched_rule", "NONE") for e in events))
    sev_labels = sorted(set(e.get("severity", "LOW") for e in events))
    target_labels = sorted(set(e.get("llm", {}).get("classification", "UNKNOWN") for e in events))

    all_labels = source_labels + rule_labels + sev_labels + target_labels
    label_map = {lbl: i for i, lbl in enumerate(all_labels)}

    sources, targets, values = [], [], []

    def _add_pairs(pair_counts):
        for (src, tgt), val in pair_counts.items():
            if src in label_map and tgt in label_map:
                sources.append(label_map[src])
                targets.append(label_map[tgt])
                values.append(val)

    type_rule, rule_sev, sev_class = {}, {}, {}
    for e in events:
        src = _event_source(e)
        rule = e.get("matched_rule", "NONE")
        sev = e.get("severity", "LOW")
        cls = e.get("llm", {}).get("classification", "UNKNOWN")
        type_rule[(src, rule)] = type_rule.get((src, rule), 0) + 1
        rule_sev[(rule, sev)] = rule_sev.get((rule, sev), 0) + 1
        sev_class[(sev, cls)] = sev_class.get((sev, cls), 0) + 1

    _add_pairs(type_rule)
    _add_pairs(rule_sev)
    _add_pairs(sev_class)

    palette = ["#00D4FF", "#BF5AF2", "#30D158", "#FFD60A", "#FF9500", "#FF2D55"]
    node_colors = [palette[i % len(palette)] for i in range(len(all_labels))]

    fig = go.Figure(data=[go.Sankey(
        node=dict(pad=15, thickness=15, line=dict(color="#1A3A5C", width=1),
                  label=all_labels, color=node_colors),
        link=dict(source=sources, target=targets, value=values,
                  color="rgba(0,212,255,.08)"),
    )])
    fig.update_layout(**PL, title_text="EDR ATTACK PIPELINE FLOW",
                      title_font=dict(size=12, family="Share Tech Mono"), height=320)
    return fig


def render_threat_heatmap(df: pd.DataFrame) -> go.Figure:
    """Temporal threat-score heatmap by day/hour."""
    fig = go.Figure()
    if df.empty:
        fig.update_layout(**PL, height=200)
        return fig

    df = df.copy()
    df["dt"] = pd.to_datetime(df["visit_time"], errors="coerce")
    df["hr"] = df["dt"].dt.hour
    df["day"] = df["dt"].dt.strftime("%a %m/%d")
    pivot = df.pivot_table(index="day", columns="hr", values="threat_score", aggfunc="mean").fillna(0)
    if not pivot.empty:
        fig.add_trace(go.Heatmap(
            z=pivot.values, x=pivot.columns.tolist(), y=pivot.index.tolist(),
            colorscale=[[0, "#020C18"], [.3, "#0E2845"], [.6, "#00D4FF"], [.8, "#FF9500"], [1, "#FF2D55"]],
            hovertemplate="Hour %{x}:00 | %{y}<br>Avg Score: %{z:.0f}<extra></extra>",
            showscale=True, colorbar=dict(thickness=10, tickfont=dict(size=8)),
        ))
        fig.update_layout(**PL, height=200, xaxis_title="Hour of Day (UTC)")
        fig.update_layout(xaxis=dict(**GRD, tickmode="linear", dtick=2), yaxis=dict(**GRD))
    return fig
