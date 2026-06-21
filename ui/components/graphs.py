"""NetworkX process tree graph for EDR dashboard."""

import networkx as nx
import plotly.graph_objects as go
from typing import List, Dict, Any, Optional

PL = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Share Tech Mono", color="#7BAFD4", size=10),
    margin=dict(l=10, r=10, t=10, b=10),
)


def render_process_tree(processes: Optional[List[Dict[str, Any]]] = None) -> Optional[go.Figure]:
    """Build parent/child process graph. Returns None if no process data."""
    if not processes:
        return None

    G = nx.DiGraph()
    for p in processes:
        pid = p.get("PID") or p.get("process_id")
        ppid = p.get("PPID") or p.get("parent_process_id")
        name = p.get("ImageFileName") or p.get("process_name") or "Unknown"
        cmd = p.get("cmdline") or p.get("Args") or name
        if not pid:
            continue
        is_malicious = (
            any(x in name.lower() for x in ("sliver", "beacon", "mimikatz", "malfind"))
            or any(x in str(cmd).lower() for x in ("-enc", "bypass", "downloadstring"))
        )
        G.add_node(pid, name=name, cmdline=cmd, pid=pid, malicious=is_malicious)
        if ppid and ppid != 0:
            G.add_edge(ppid, pid)

    if not G.nodes():
        return None

    pos = nx.spring_layout(G, seed=42, k=1.5, iterations=40)
    edge_x, edge_y = [], []
    for a, b in G.edges():
        x0, y0 = pos[a]
        x1, y1 = pos[b]
        edge_x += [x0, x1, None]
        edge_y += [y0, y1, None]

    node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
    for node in G.nodes():
        x, y = pos[node]
        name = G.nodes[node].get("name", "Unknown")
        pid = G.nodes[node].get("pid", 0)
        cmd = G.nodes[node].get("cmdline", "")
        mal = G.nodes[node].get("malicious", False)
        node_x.append(x)
        node_y.append(y)
        node_text.append(f"<b>{name}</b> (PID: {pid})<br>Cmd: {str(cmd)[:60]}")
        node_color.append("#FF2D55" if mal else "#00D4FF" if pid == 688 else "#30D158")
        node_size.append(18 if mal else 12)

    fig = go.Figure(data=[
        go.Scatter(x=edge_x, y=edge_y, mode="lines",
                   line=dict(width=1, color="rgba(30, 60, 90, 0.4)"), hoverinfo="none"),
        go.Scatter(x=node_x, y=node_y, mode="markers+text",
                   text=[G.nodes[n].get("name", "") for n in G.nodes()],
                   textposition="top center",
                   textfont=dict(family="Share Tech Mono", size=9, color="#7BAFD4"),
                   hovertext=node_text, hoverinfo="text",
                   marker=dict(showscale=False, color=node_color, size=node_size,
                               line=dict(width=1, color="#020C18"))),
    ])
    fig.update_layout(**PL, showlegend=False, height=320)
    fig.update_layout(
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
    )
    return fig
