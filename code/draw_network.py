import math

import numpy as np
import networkx as nx
import matplotlib

matplotlib.use('TkAgg')
import matplotlib.pyplot as plt


def draw_ip_network(ip_array: list):
    G = nx.DiGraph()
    edge_weights = [w.send_count for w in ip_array]
    max_item = max(edge_weights)
    edge_weights = np.divide(edge_weights, max_item)
    node_weights = [w.send_size for w in ip_array]
    node_weights = zoom(node_weights)
    for item in ip_array:
        G.add_edge(item.src, item.des, size=str(item.send_size), num=str(item.send_count))
    node_number = len(G.nodes())

    edge_labels = {}
    for edge in G.edges:
        edge_labels[edge] = (G[edge[0]][edge[1]])

    pos = nx.spring_layout(G)

    nx.draw(G, pos,
            node_color=range(node_number),
            with_labels=True,
            edge_color=edge_weights,
            width=3,
            font_size=8,
            cmap=plt.cm.Dark2,
            edge_cmap=plt.cm.Blues,
            node_size=node_weights,
            )
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=8)
    plt.show()


def zoom(weights: list):
    res = []
    max_it = max(weights)
    for it in weights:
        if max_it > 10000:
            res.append(it / 15)
        else:
            res.append(it)
    return res
