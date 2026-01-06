import csv
from collections import Counter
import matplotlib.pyplot as plt

def charger_csv(chemin_csv):
    ports = []
    with open(chemin_csv, "r", encoding="utf-8-sig") as f:
        lecteur = csv.DictReader(f, delimiter=";")
        for ligne in lecteur:
            ports.append(ligne["dst_port"])
    return ports

def compter_ports(ports):
    return Counter(ports)

def tracer_barres(compteur_ports, titre="Nombre de trames par port de destination"):
    ports = list(compteur_ports.keys())
    valeurs = list(compteur_ports.values())

    plt.figure(figsize=(8, 4))
    plt.bar(ports, valeurs, color="steelblue")
    plt.xlabel("Port de destination")
    plt.ylabel("Nombre de trames")
    plt.title(titre)
    plt.grid(axis="y", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    chemin = "dump.csv"  # adapte si besoin
    ports = charger_csv(chemin)
    compteur = compter_ports(ports)
    tracer_barres(compteur)
