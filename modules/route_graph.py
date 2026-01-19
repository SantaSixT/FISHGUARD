import graphviz

def generate_route_graph(ips):
    """Génère un objet Graphviz montrant la route des IPs"""
    if not ips: return None
    try:
        dot = graphviz.Digraph(comment='Email Route', format='png')
        dot.attr(rankdir='LR') # Gauche à Droite
        
        # Noeuds
        prev_node = "Expéditeur"
        dot.node(prev_node, shape='ellipse', style='filled', fillcolor='lightgrey')
        
        for i, ip in enumerate(reversed(ips)): # On inverse pour avoir l'ordre chrono
            node_name = f"Relais {i+1}\n({ip})"
            dot.node(node_name, shape='box', style='filled', fillcolor='#e1f5fe')
            dot.edge(prev_node, node_name)
            prev_node = node_name
            
        dot.node("Votre Boîte", shape='ellipse', style='filled', fillcolor='lightgreen')
        dot.edge(prev_node, "Votre Boîte")
        
        return dot
    except Exception:
        return None # Graphviz probablement pas installé sur le système