import networkx as nx
import matplotlib.pyplot as plt
from collections import deque
import heapq
import logging
import os

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

def load_graph_from_file(filename):
    """
    Loads a network topology from a file and identifies attack sources.
    Returns a directed graph: (Graph object, SuperSource name, list of identified attackers)
    Format: source,target,weight,capacity,type(A/N)
    """

    # Initialize the network graph
    # Using a directed graph since network traffic (and attacks) have a direction
    G = nx.DiGraph()
    attackers = []
    # Initialize SuperSource as "the parent of attackers"
    super_source = "SuperSource"
    
    if not os.path.exists(filename):
        logger.error(f"File {filename} not found! Please create it.")
        return None, None, None

    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip empty lines or comments
                if not line or line.startswith('#'):
                    continue
                
                # Unpack all five columns
                source, target, weight, capacity, node_type = line.split(',')
                
                # Add the primary network edge
                G.add_edge(source, target, 
                           weight=int(weight), 
                           capacity=int(capacity))
                
                # If marked as 'A', track this as an attack entry point
                if node_type.strip().upper() == 'A' and source not in attackers:
                    attackers.append(source)
        
        # LINKING PHASE: Connect SuperSource to all 'A' type nodes
        for attacker in attackers:
            # We use infinite capacity so the bottleneck is always the network, 
            # not the virtual source itself.
            G.add_edge(super_source, attacker, weight=0, capacity=float('inf'))
            
        logger.info(f"Successfully loaded graph from {filename}. Identified {len(attackers)} attackers.")
        return G, super_source, attackers

    except Exception as e:
        logger.error(f"Error parsing file: {e}")
        return None, None, None

def bfs(graph, start_node, target_node, residual=None):
    """
    A universal BFS pathfinder. 
    If residual is None: Acts as a standard topology search (finds the shortest path based strictly on the fewest network hops).
    If residual is provided: Acts as a capacity-aware search for Edmonds-Karp.
    """
    
    # Queue stores the path taken so far
    queue = deque([[start_node]])
    visited = {start_node}

    while queue:
        # Get the first path in the queue
        path = queue.popleft()
        current_node = path[-1]

        # If we reached the target, return the path that got us here
        if current_node == target_node:
            return path

        # Determine if we are looking at the original graph or the residual graph
        if residual is not None:
            # Capacity-aware search: check if current link has bandwidth > 0
            for v, capacity in residual[current_node].items():
                if v not in visited and capacity > 0:
                    visited.add(v)
                    queue.append(path + [v])
        else:
            # Standard search: just check if nodes are physically connected
            for v in graph.neighbors(current_node):
                # If it's not visited, create a new path by appending the neighbor, then queue it
                if v not in visited:
                    visited.add(v)
                    queue.append(path + [v])
                
    # Root Case: No path found
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

# Mitigation Algorithms

def edmonds_karp(graph, source, target):
    """
    Calculates the Maximum Flow (worst-case DDoS volume) from source to target.
    Uses BFS function and returns the total max flow and the final residual graph.
    """ 

    # Initialize residual graph
    residual = {node: {} for node in graph.nodes()}
    for u, v, data in graph.edges(data=True):
        cap = data.get('capacity', 0)
        residual[u][v] = cap
        if u not in residual[v]: residual[v][u] = 0

    max_flow = 0

    # Use the BFS to find paths with available capacity
    while True:
        path = bfs(graph, source, target, residual=residual)
        
        if not path:
            break # No more capacity available

        # Calculate bottleneck and update residual
        path_flow = min(residual[path[i]][path[i+1]] for i in range(len(path) - 1))
        max_flow += path_flow
        
        for i in range(len(path) - 1):
            u, v = path[i], path[i+1]
            residual[u][v] -= path_flow
            residual[v][u] += path_flow

    return max_flow, residual

def minimum_cut(graph, source, residual_graph):
    """
    Finds the exact network links to severe (firewall rules) to stop the attack entirely.
    """

    # Find all nodes the attacker can still reach in the "maxed out" residual graph
    reachable = set([source])
    queue = deque([source])

    while queue:
        u = queue.popleft()
        for v, remaining_capacity in residual_graph[u].items():
            if v not in reachable and remaining_capacity > 0:
                reachable.add(v)
                queue.append(v)

    # The critical "Cut" edges are the original links that bridge the reachable attacker zone to the protected target zone.
    min_cut_edges = []
    for u in reachable:
        for v in graph.neighbors(u):
            if v not in reachable:
                min_cut_edges.append((u, v))

    return min_cut_edges

def main():
    logger.info("Initializing the network graph...")

    # Load graph from external file
    G, botnet_origin, attackers_node = load_graph_from_file("network_input.txt")
    
    # Stop if the file is missing or broken
    if G is None or attackers_node is None:
        logger.error("Failed to initialize graph. Check your network_input.txt file.")
        return

    # Algorithm 1: Shortest Path (BFS and Dijkstra)
    # Identifying the least-cost attack route from attackers to Target
    target_node = 'Target'

    sample_attacker = attackers_node[0] 
    logger.info(f"Running Attack Routing Algorithms ({sample_attacker} -> {target_node})...")
    
    # Execute BFS
    logger.info("Fewest Hops Routing Analysis by BFS:")
    for attacker in attackers_node:
        bfs_path = bfs(G, attacker, target_node)
        if bfs_path:
            logger.info(f"  > {attacker} -> Target: {len(bfs_path)-1} hops | Path: {bfs_path}")
        else:
            logger.warning(f"  > {attacker}: No path to target found!")

    # Execute Dijkstra
    logger.info("Least-Cost Attacker Routing Analysis by Dijkstra:")
    all_dijkstra_paths = []
    for attacker in attackers_node:
        dijkstra_path = dijkstra(G, attacker, target_node)
        if dijkstra_path:
            all_dijkstra_paths.append(dijkstra_path)
        logger.info(f"  > {attacker} routing path: {dijkstra_path}")

    logger.info("Calculating Infrastructure Vulnerability...")

    # Algorithm 2: Centrality (Betweenness Centrality)
    # Identifying which nodes act as the biggest bottlenecks or critical infrastructure
    centrality = betweenness_centrality(G)
    logger.info("  - Node Centrality Scores (Structural Bottlenecks; higher means more critical):")
    for node, score in sorted(centrality.items(), key=lambda item: item[1], reverse=True):
        logger.info(f"    > {node}: {score}")

    logger.info("Executing Mitigation Strategies (Max Flow & Min Cut)...")
    
    # Calculate Maximum Flow (Total DDoS Volume)
    max_bandwidth, residual_graph = edmonds_karp(G, botnet_origin, target_node)
    logger.info(f"  - Maximum Attack Volume (Ford-Fulkerson/Edmonds-Karp): {max_bandwidth} units/sec")

    # Calculate Minimum Cut (Choke Points for XDP Firewall)
    critical_links = minimum_cut(G, botnet_origin, residual_graph)
    logger.info(f"  - CRITICAL MITIGATION: To stop the attack entirely, deploy firewall rules on these exact links:")
    for link in critical_links:
        logger.info(f"    > Block traffic from {link[0]} to {link[1]}")

    # Visualization using Matplotlib
    logger.info("Generating Topology Visualization...")
    
    plt.figure(figsize=(12, 7))
    pos = nx.spring_layout(G, seed=42) 

    # Draw base nodes (size based on Betweenness Centrality)
    node_sizes = [2000 + (centrality.get(node, 0) * 500) for node in G.nodes()]
    nx.draw_networkx_nodes(G, pos, node_color='lightblue', node_size=node_sizes)
    
    # Draw base edges
    nx.draw_networkx_edges(G, pos, arrowstyle='->', arrowsize=20, edge_color='lightgray', alpha=0.6)
    
    # 1. Highlight the Dijkstra Attack Path in RED
    if dijkstra_path:
        path_edges = list(zip(dijkstra_path, dijkstra_path[1:]))
        nx.draw_networkx_edges(G, pos, edgelist=path_edges, edge_color='red', width=3)

    # 2. Highlight the Min-Cut (Firewall Points) in ORANGE/BOLD
    if critical_links:
        nx.draw_networkx_edges(G, pos, edgelist=critical_links, edge_color='orange', width=5, style='dashed')

    # 3. FIX: Create Proxy Artists for the Legend
    # This manually tells the legend what colors and styles to show
    from matplotlib.lines import Line2D
    legend_elements = [
        Line2D([0], [0], color='red', lw=3, label='Attack Path (Dijkstra)'),
        Line2D([0], [0], color='orange', lw=3, ls='--', label='Min-Cut (XDP Firewall Points)')
    ]

    # Labels and Metadata
    nx.draw_networkx_labels(G, pos, font_size=10, font_weight='bold')
    edge_labels = nx.get_edge_attributes(G, 'weight')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels)

    plt.title("DDoS Simulation: Attack Vectors vs. Mitigation Choke Points\n"
              "Node Size = Centrality | Red = Attack Path | Orange Dashed = Firewall Placement", fontsize=12)
    
    # Pass the proxy artists into the legend
    plt.legend(handles=legend_elements, loc='upper left', frameon=True)
    
    plt.axis('off')
    plt.tight_layout()
    
    output_filename = "simulation_output.png"
    plt.savefig(output_filename, dpi=300)
    logger.info(f"Success: Visualization saved as '{output_filename}'")
    
    # plt.show() # Uncomment this line if you want the window to pop up when you run it!

if __name__ == "__main__":
    main()