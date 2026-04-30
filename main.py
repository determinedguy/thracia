import networkx as nx
import matplotlib.pyplot as plt

def main():
    # 1. Initialize the Network Graph
    # Using a directed graph since network traffic (and attacks) have a direction
    G = nx.DiGraph()

    # Add edges with 'weight' (for shortest path) and 'capacity' (for max flow later)
    edges = [
        ('Attacker1', 'RouterA', {'weight': 1, 'capacity': 100}),
        ('Attacker2', 'RouterB', {'weight': 2, 'capacity': 50}),
        ('RouterA', 'RouterC', {'weight': 1, 'capacity': 80}),
        ('RouterA', 'RouterD', {'weight': 4, 'capacity': 40}),
        ('RouterB', 'RouterD', {'weight': 2, 'capacity': 60}),
        ('RouterC', 'Target', {'weight': 1, 'capacity': 100}),
        ('RouterD', 'Target', {'weight': 2, 'capacity': 120}),
        ('RouterC', 'RouterD', {'weight': 1, 'capacity': 30}) # Cross-link
    ]
    G.add_edges_from(edges)

    # 2. Algorithm 1: Shortest Path (Dijkstra)
    # Identifying the least-cost attack route from Attacker1 to Target
    source_node = 'Attacker1'
    target_node = 'Target'
    
    try:
        shortest_path = nx.shortest_path(G, source=source_node, target=target_node, weight='weight')
        print(f"[*] Least-cost attack path ({source_node} -> {target_node}): {shortest_path}")
    except nx.NetworkXNoPath:
        print(f"[*] No path found between {source_node} and {target_node}")
        shortest_path = []

    # 3. Algorithm 2: Centrality (Betweenness Centrality)
    # Identifying which nodes act as the biggest bottlenecks or critical infrastructure
    centrality = nx.betweenness_centrality(G, weight='weight')
    print("[*] Node Centrality Scores (Higher means more critical):")
    for node, score in sorted(centrality.items(), key=lambda item: item[1], reverse=True):
        print(f"    - {node}: {score:.4f}")

    # 4. Visualization using Matplotlib
    plt.figure(figsize=(10, 6))
    
    # Generate a layout for the nodes
    pos = nx.spring_layout(G, seed=42) 

    # Draw all nodes and edges
    nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=2000)
    nx.draw_networkx_edges(G, pos, arrowstyle='->', arrowsize=20, edge_color='gray')
    nx.draw_networkx_labels(G, pos, font_size=10, font_weight='bold')

    # Highlight the shortest attack path in RED
    if shortest_path:
        path_edges = list(zip(shortest_path, shortest_path[1:]))
        nx.draw_networkx_nodes(G, pos, nodelist=shortest_path, node_color='salmon', node_size=2000)
        nx.draw_networkx_edges(G, pos, edgelist=path_edges, edge_color='red', width=3, arrowstyle='->', arrowsize=20)

    # Add edge weight labels for visual clarity
    edge_labels = nx.get_edge_attributes(G, 'weight')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)

    plt.title("DDoS Attack Path Simulation (PoC)\nRed = Shortest Attack Path", fontsize=14)
    plt.axis('off')
    plt.tight_layout()
    
    # Save the plot as an image to include in your report
    plt.savefig("simulation_output.png", dpi=300)
    print("\n[*] Visualization saved as 'simulation_output.png'")
    plt.show()

if __name__ == "__main__":
    main()