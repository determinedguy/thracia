import networkx as nx
import matplotlib.pyplot as plt
from collections import deque
import heapq
import logging

# ==========================================
# 0. LOGGER CONFIGURATION
# ==========================================

# This sets up the formal logging format (Timestamp - Level - Message)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler("simulation_trace.txt"), # Saves output to this text file
        logging.StreamHandler()                      # Prints output to the terminal
    ]
)
logger = logging.getLogger(__name__)

def bfs(graph, start_node, target_node):
    """Finds the shortest path based strictly on the fewest network hops."""

    # Queue stores the path taken so far
    queue = deque([[start_node]])
    visited = set([start_node])

    while queue:
        # Get the first path in the queue
        path = queue.popleft()
        current_node = path[-1]

        # If we reached the target, return the path that got us here
        if current_node == target_node:
            return path

        # Check all neighboring routers
        for neighbor in graph.neighbors(current_node):
            if neighbor not in visited:
                visited.add(neighbor)
                # Create a new path by appending the neighbor, then queue it
                new_path = list(path)
                new_path.append(neighbor)
                queue.append(new_path)
                
    # Else, no path found
    return None

def dijkstra(graph, start_node, target_node):
    """Finds the least-cost routing path based on edge weights."""

    # Priority queue stores tuples: (cumulative_cost, current_node, path_history)
    priority_queue = [(0, start_node, [start_node])]
    visited = set()

    while priority_queue:
        # Pop the path with the absolute lowest cost so far
        current_cost, current_node, path = heapq.heappop(priority_queue)

        if current_node in visited:
            continue
            
        visited.add(current_node)

        # If we reached the target, return the path
        if current_node == target_node:
            return path

        # Explore neighbors and calculate their routing costs
        for neighbor in graph.neighbors(current_node):
            if neighbor not in visited:
                # Extract the weight we assigned to the edge (default to 1 if missing)
                edge_weight = graph[current_node][neighbor].get('weight', 1)
                total_cost = current_cost + edge_weight
                
                # Push the new path into the priority queue
                heapq.heappush(priority_queue, (total_cost, neighbor, path + [neighbor]))

    # Else, no path found 
    return None

def betweenness_centrality(graph):
    """
    Naive calculation of Betweenness Centrality to identify structural bottlenecks.
    Counts how many times a node acts as a bridge on the shortest path between all pairs.
    """

    # Initialize every node's score to 0
    centrality_scores = {node: 0.0 for node in graph.nodes()}
    nodes_list = list(graph.nodes())
    
    # Iterate through every possible pair of source and target nodes
    for source in nodes_list:
        for target in nodes_list:
            if source == target:
                continue # Skip routing a node to itself
                
            # Find the shortest path between the pair with Dijkstra
            path = dijkstra(graph, source, target)
                
            # If a path exists, give +1 score to every node that acts as a bridge
            # Slice [1:-1] to exclude the source and the target themselves
            # If no path exists between these two nodes, just ignore them
            if path is not None:
                # Give +1 score to every node that acts as a bridge
                for intermediate_node in path[1:-1]:
                    centrality_scores[intermediate_node] += 1
                
    return centrality_scores
def main():
    logger.info("Initializing the network graph...")
    # Initialize the network graph
    # Using a directed graph since network traffic (and attacks) have a direction
    G = nx.DiGraph()

    # Define the topology (Attacker -> Routers -> Target)
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

    # Algorithm 1: Shortest Path (BFS and Dijkstra)
    # Identifying the least-cost attack route from Attacker1 to Target
    source_node = 'Attacker1'
    target_node = 'Target'

    logger.info(f"Running Attack Routing Algorithms ({source_node} -> {target_node})")
    
    # Execute BFS
    bfs_path = bfs(G, source_node, target_node)
    logger.info(f"  - BFS (Fewest Hops): {bfs_path}")

    # Execute Dijkstra
    dijkstra_path = dijkstra(G, source_node, target_node)
    logger.info(f"  - Dijkstra (Least-Cost Path): {dijkstra_path}")

    logger.info("Calculating Infrastructure Vulnerability...")

    # Algorithm 2: Centrality (Betweenness Centrality)
    # Identifying which nodes act as the biggest bottlenecks or critical infrastructure
    centrality = betweenness_centrality(G)
    logger.info("  - Node Centrality Scores (Structural Bottlenecks; higher means more critical):")
    for node, score in sorted(centrality.items(), key=lambda item: item[1], reverse=True):
        logger.info(f"    > {node}: {score}")

    # Visualization using Matplotlib
    logger.info("Generating Topology Visualization...")
    
    plt.figure(figsize=(10, 6))
    pos = nx.spring_layout(G, seed=42) 

    # Scale node sizes visually based on their centrality score so vulnerabilities pop out
    node_sizes = [2000 + (centrality.get(node, 0) * 200) for node in G.nodes()]

    nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=node_sizes)
    nx.draw_networkx_edges(G, pos, arrowstyle='->', arrowsize=20, edge_color='gray')
    nx.draw_networkx_labels(G, pos, font_size=10, font_weight='bold')

    # Highlight the Dijkstra (Least-Cost) attack path in RED
    if dijkstra_path:
        path_edges = list(zip(dijkstra_path, dijkstra_path[1:]))
        nx.draw_networkx_nodes(G, pos, nodelist=dijkstra_path, node_color='salmon', node_size=[2000 + (centrality.get(n, 0) * 200) for n in dijkstra_path])
        nx.draw_networkx_edges(G, pos, edgelist=path_edges, edge_color='red', width=3, arrowstyle='->', arrowsize=20)

    # Add edge weight labels
    edge_labels = nx.get_edge_attributes(G, 'weight')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)

    plt.title("DDoS Attack Path Simulation\nRed = Dijkstra Attack Path | Node Size = Centrality Vulnerability", fontsize=14)
    plt.axis('off')
    plt.tight_layout()
    
    output_filename = "simulation_output.png"
    plt.savefig(output_filename, dpi=300)
    logger.info(f"Success: Visualization saved as '{output_filename}'")
    
    # plt.show() # Uncomment this line if you want the window to pop up when you run it!

if __name__ == "__main__":
    main()