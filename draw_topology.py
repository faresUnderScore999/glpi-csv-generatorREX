#!/usr/bin/env python3
"""
Network Topology Drawer
Reads assets_inventory.csv and generates a network topology diagram.
"""

import csv
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import networkx as nx
from collections import defaultdict

CSV_FILE = "assets_inventory.csv"
OUTPUT_FILE = "network_topology.png"

# ── Read CSV ──────────────────────────────────────────────────────────────
def read_assets(path):
    devices = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            hostname = row["hostname"].strip()
            devices[hostname] = {
                "type": row["type"].strip(),
                "hostname": hostname,
                "ip": row["ip"].strip(),
                "location": row["location"].strip(),
                "status": row["status"].strip(),
                "vendor": row["vendor"].strip(),
                "model": row["model"].strip(),
                "network_zone": row["network_zone"].strip(),
            }
    return devices


# ── Build topology edges ──────────────────────────────────────────────────
def build_edges(devices):
    """
    Define logical connections based on network zones, locations, and device types.
    """
    edges = []

    # Group devices by network zone and location
    by_zone = defaultdict(list)
    by_location = defaultdict(list)
    for d in devices.values():
        by_zone[d["network_zone"]].append(d["hostname"])
        by_location[d["location"]].append(d["hostname"])

    # ── Core infrastructure ────────────────────────────────────────────
    router = "ROUTER-MAIN"
    switch = "SWITCH-MAIN"

    if router in devices and switch in devices:
        edges.append((router, switch, "trunk"))

    # ── Servers connect to switch ──────────────────────────────────────
    servers = [h for h, d in devices.items() if d["type"] == "SERVER"]
    for srv in servers:
        if switch in devices:
            edges.append((switch, srv, "lan"))

    # ── Access Points connect to switch ────────────────────────────────
    aps = [h for h, d in devices.items() if d["type"] == "NETWORK" and h.startswith("AP")]
    for ap in aps:
        if switch in devices:
            edges.append((switch, ap, "lan"))

    # ── Endpoints connect to nearest AP or switch ──────────────────────
    # Floor 1 endpoints → AP-FLOOR1
    floor1_ap = "AP-FLOOR1"
    floor1_endpoints = [
        h for h, d in devices.items()
        if d["type"] == "ENDPOINT" and d["location"] == "Floor 1"
    ]
    for ep in floor1_endpoints:
        if floor1_ap in devices:
            edges.append((floor1_ap, ep, "wifi"))
        elif switch in devices:
            edges.append((switch, ep, "lan"))

    # Floor 2 endpoints → AP-FLOOR2
    floor2_ap = "AP-FLOOR2"
    floor2_endpoints = [
        h for h, d in devices.items()
        if d["type"] == "ENDPOINT" and d["location"] == "Floor 2"
    ]
    for ep in floor2_endpoints:
        if floor2_ap in devices:
            edges.append((floor2_ap, ep, "wifi"))
        elif switch in devices:
            edges.append((switch, ep, "lan"))

    # Warehouse endpoint → switch
    warehouse_ep = "DESKTOP-003"
    if warehouse_ep in devices and switch in devices:
        edges.append((switch, warehouse_ep, "lan"))

    return edges


# ── Drawing ───────────────────────────────────────────────────────────────
def draw_topology(devices, edges):
    G = nx.Graph()

    # Add nodes
    for name, info in devices.items():
        G.add_node(name, **info)

    # Add edges with type attribute
    for src, dst, etype in edges:
        G.add_edge(src, dst, link_type=etype)

    # ── Layout ─────────────────────────────────────────────────────────
    # Use a hierarchical layout: router at top, switch below, then servers/APs, then endpoints
    pos = {}

    # Layer 0: Router
    router = "ROUTER-MAIN"
    if router in G:
        pos[router] = (0, 3)

    # Layer 1: Switch
    switch = "SWITCH-MAIN"
    if switch in G:
        pos[switch] = (0, 2)

    # Layer 2: Servers (left) and APs (right)
    servers = sorted([n for n in G.nodes if devices[n]["type"] == "SERVER"])
    aps = sorted([n for n in G.nodes if devices[n]["type"] == "NETWORK" and n.startswith("AP")])

    for i, srv in enumerate(servers):
        pos[srv] = (-1.5 - i * 0.5, 1)

    for i, ap in enumerate(aps):
        pos[ap] = (1.5 + i * 0.5, 1)

    # Layer 3: Endpoints — group by location
    floor1_eps = sorted([
        n for n in G.nodes
        if devices[n]["type"] == "ENDPOINT" and devices[n]["location"] == "Floor 1"
    ])
    floor2_eps = sorted([
        n for n in G.nodes
        if devices[n]["type"] == "ENDPOINT" and devices[n]["location"] == "Floor 2"
    ])
    warehouse_eps = sorted([
        n for n in G.nodes
        if devices[n]["type"] == "ENDPOINT" and devices[n]["location"] == "Warehouse"
    ])

    for i, ep in enumerate(floor1_eps):
        pos[ep] = (-1.0 + i * 0.8, 0)

    for i, ep in enumerate(floor2_eps):
        pos[ep] = (1.0 + i * 0.8, 0)

    for i, ep in enumerate(warehouse_eps):
        pos[ep] = (-1.0, -1)

    # Any remaining nodes
    placed = set(pos.keys())
    unplaced = [n for n in G.nodes if n not in placed]
    for i, n in enumerate(unplaced):
        pos[n] = (3, 3 - i * 0.5)

    # ── Node styling ───────────────────────────────────────────────────
    node_colors = []
    node_shapes = []  # 'o' circle, 's' square, 'D' diamond
    node_sizes = []
    edge_colors = []
    edge_styles = []

    for n in G.nodes:
        dtype = devices[n]["type"]
        status = devices[n]["status"]

        # Base color by type
        if dtype == "NETWORK":
            if "AP" in n:
                base_color = "#4A90D9"  # blue for AP
            else:
                base_color = "#1E3A5F"  # dark blue for router/switch
            shape = "s"
            size = 1200
        elif dtype == "SERVER":
            base_color = "#2E8B57"  # green
            shape = "D"
            size = 1100
        else:  # ENDPOINT
            base_color = "#D97A29"  # orange
            shape = "o"
            size = 900

        # Adjust brightness by status
        if status == "INACTIVE":
            base_color = "#CCCCCC"
        elif status == "MAINTENANCE":
            # lighten / desaturate
            base_color = "#E8C87A"

        node_colors.append(base_color)
        node_shapes.append(shape)
        node_sizes.append(size)

    # ── Edge styling ───────────────────────────────────────────────────
    for u, v, data in G.edges(data=True):
        etype = data.get("link_type", "lan")
        if etype == "trunk":
            edge_colors.append("#1E3A5F")
            edge_styles.append("solid")
        elif etype == "wifi":
            edge_colors.append("#4A90D9")
            edge_styles.append("dashed")
        else:
            edge_colors.append("#888888")
            edge_styles.append("solid")

    # ── Draw using matplotlib with separate shape groups ───────────────
    fig, ax = plt.subplots(1, 1, figsize=(16, 10))
    fig.patch.set_facecolor("#F5F5F5")
    ax.set_facecolor("#F5F5F5")

    # Draw edges
    for idx, (u, v, data) in enumerate(G.edges(data=True)):
        color = edge_colors[idx] if idx < len(edge_colors) else "#888888"
        style = edge_styles[idx] if idx < len(edge_styles) else "solid"
        lw = 2.5 if data.get("link_type") == "trunk" else 1.5
        ax.plot(
            [pos[u][0], pos[v][0]],
            [pos[u][1], pos[v][1]],
            color=color,
            linestyle=style,
            linewidth=lw,
            alpha=0.7,
            zorder=1,
        )

    # Draw nodes by shape (matplotlib scatter doesn't support mixed shapes easily)
    for shape in set(node_shapes):
        indices = [i for i, s in enumerate(node_shapes) if s == shape]
        nodes_subset = [list(G.nodes)[i] for i in indices]
        xs = [pos[n][0] for n in nodes_subset]
        ys = [pos[n][1] for n in nodes_subset]
        colors = [node_colors[i] for i in indices]
        sizes = [node_sizes[i] for i in indices]

        marker_map = {"o": "o", "s": "s", "D": "D"}
        marker = marker_map.get(shape, "o")

        ax.scatter(xs, ys, c=colors, s=sizes, marker=marker,
                   edgecolors="#333333", linewidths=1.5, zorder=2)

    # ── Labels ─────────────────────────────────────────────────────────
    for n in G.nodes:
        info = devices[n]
        ip = info["ip"]
        status = info["status"]
        label = f"{n}\n{ip}\n[{status}]"
        ax.annotate(
            label,
            pos[n],
            textcoords="offset points",
            xytext=(0, -22 if node_shapes[list(G.nodes).index(n)] == "o" else -26),
            ha="center",
            va="top",
            fontsize=7,
            fontweight="bold",
            color="#222222",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="white", edgecolor="gray", alpha=0.8),
            zorder=3,
        )

    # ── Legend ─────────────────────────────────────────────────────────
    legend_elements = [
        mpatches.Patch(facecolor="#1E3A5F", edgecolor="#333333", label="Router / Switch"),
        mpatches.Patch(facecolor="#4A90D9", edgecolor="#333333", label="Access Point"),
        mpatches.Patch(facecolor="#2E8B57", edgecolor="#333333", label="Server"),
        mpatches.Patch(facecolor="#D97A29", edgecolor="#333333", label="Endpoint"),
        mpatches.Patch(facecolor="#CCCCCC", edgecolor="#333333", label="Inactive"),
        mpatches.Patch(facecolor="#E8C87A", edgecolor="#333333", label="Maintenance"),
        plt.Line2D([0], [0], color="#1E3A5F", linewidth=2.5, label="Trunk"),
        plt.Line2D([0], [0], color="#4A90D9", linewidth=1.5, linestyle="dashed", label="WiFi"),
        plt.Line2D([0], [0], color="#888888", linewidth=1.5, label="LAN"),
    ]
    ax.legend(handles=legend_elements, loc="upper left", fontsize=8,
              framealpha=0.9, edgecolor="#333333")

    ax.set_title("Network Topology", fontsize=18, fontweight="bold", pad=20)
    ax.axis("off")
    plt.tight_layout()
    plt.savefig(OUTPUT_FILE, dpi=200, bbox_inches="tight")
    plt.close()
    print(f"Topology diagram saved to {OUTPUT_FILE}")


# ── Main ──────────────────────────────────────────────────────────────────
def main():
    print(f"Reading assets from {CSV_FILE} ...")
    devices = read_assets(CSV_FILE)
    print(f"  Found {len(devices)} devices")

    edges = build_edges(devices)
    print(f"  Built {len(edges)} connections")

    draw_topology(devices, edges)


if __name__ == "__main__":
    main()