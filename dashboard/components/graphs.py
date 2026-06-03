"""
dashboard/components/graphs.py — Reusable NetworkX Process Trees Mappings
========================================================================
Draws hierarchical relationship trees for running system processes or
memory forensics injections, mapping parents to children.
"""

import networkx as nx
import plotly.graph_objects as go
from typing import List, Dict, Any

# Reusable Plotly layouts
PL = dict(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
          font=dict(family="Share Tech Mono", color="#7BAFD4", size=10),
          margin=dict(l=10, r=10, t=10, b=10))

def render_process_tree(processes: List[Dict[str, Any]]) -> go.Figure:
    """
    Build a Directed Graph representing process parents & children using NetworkX,
    rendering it via Plotly Scatter plots. Highlight suspicious injected nodes.
    """
    G = nx.DiGraph()
    
    if not processes:
        # Default mock processes list if empty
        processes = [
            {"PID": 484, "PPID": 4, "ImageFileName": "smss.exe"},
            {"PID": 688, "PPID": 484, "ImageFileName": "lsass.exe"},
            {"PID": 1024, "PPID": 484, "ImageFileName": "services.exe"},
            {"PID": 1452, "PPID": 1024, "ImageFileName": "explorer.exe"},
            {"PID": 4524, "PPID": 1452, "ImageFileName": "powershell.exe"},
            {"PID": 9922, "PPID": 4524, "ImageFileName": "sliver_beacon.exe"}
        ]

    # Create nodes
    for p in processes:
        pid = p.get("PID") or p.get("process_id")
        ppid = p.get("PPID") or p.get("parent_process_id")
        name = p.get("ImageFileName") or p.get("process_name") or "Unknown"
        cmd = p.get("cmdline") or p.get("Args") or name
        
        if pid:
            is_malicious = any(x in name.lower() for x in ["sliver", "beacon", "mimikatz", "malfind"]) or \
                           any(x in str(cmd).lower() for x in ["-enc", "bypass"])
            G.add_node(pid, name=name, cmdline=cmd, pid=pid, malicious=is_malicious)
            if ppid and ppid != 0:
                G.add_edge(ppid, pid)

    # If no edges, construct root relationships
    if not G.edges():
        for p in list(G.nodes()):
            if p != 484 and G.has_node(484):
                G.add_edge(484, p)

    # spring layout spacing
    pos = nx.spring_layout(G, seed=42, k=1.5, iterations=40)
    
    # Extract edge paths
    edge_x = []
    edge_y = []
    for edge in G.edges():
        x0, y0 = pos[edge[0]]
        x1, y1 = pos[edge[1]]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    # Extract node details
    node_x = []
    node_y = []
    node_text = []
    node_color = []
    node_size = []
    
    for node in G.nodes():
        x, y = pos[node]
        node_x.append(x)
        node_y.append(y)
        
        name = G.nodes[node].get("name", "Unknown")
        pid = G.nodes[node].get("pid", 0)
        cmd = G.nodes[node].get("cmdline", "")
        mal = G.nodes[node].get("malicious", False)
        
        node_text.append(f"<b>{name}</b> (PID: {pid})<br>Cmd: {cmd[:60]}")
        node_color.append("#FF2D55" if mal else "#00D4FF" if pid == 688 else "#30D158")
        node_size.append(18 if mal else 12)

    # Plotly traces
    edge_trace = go.Scatter(
        x=edge_x, y=edge_y,
        line=dict(width=1, color="rgba(30, 60, 90, 0.4)"),
        hoverinfo="none",
        mode="lines"
    )

    node_trace = go.Scatter(
        x=node_x, y=node_y,
        mode="markers+text",
        text=[G.nodes[n].get("name", "") for n in G.nodes()],
        textposition="top center",
        textfont=dict(family="Share Tech Mono", size=9, color="#7BAFD4"),
        hoverinfo="text",
        hovertext=node_text,
        marker=dict(
            showscale=False,
            color=node_color,
            size=node_size,
            line=dict(width=1, color="#020C18")
        )
    )

    fig = go.Figure(data=[edge_trace, node_trace])
    fig.update_layout(**PL, showlegend=False, height=280) # type: ignore
    fig.update_layout(
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
    )
    return fig
