import tkinter as tk
from tkinter import filedialog, messagebox
import csv
import re
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import os
import webbrowser

# ============================================================
# 1) EXTRACTION DES TRAMES TCPDUMP
# ============================================================

pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):'
    r'.*Flags\s+\[(?P<flags>[^\]]+)\].*length\s+(?P<length>\d+)')

def split_ip_port(field):
    parts = field.rsplit('.', 1)
    return (parts[0], parts[1]) if len(parts) == 2 else (field, "")

def analyser_menaces(entetes):
    menaces = []

    # SYN suspects (scan HTTP)
    syn_http_counts = Counter()
    for ev in entetes:
        if ev["flags"] == "S" and ev["dst_port"].lower() in ("80", "http"):
            syn_http_counts[(ev["src_ip"], ev["dst_ip"])] += 1

    for (src, dst), nb in syn_http_counts.items():
        if nb >= 10:
            menaces.append(
                f"Suspicion de scan HTTP : {nb} paquets SYN depuis {src} vers {dst}."
            )

    # Trafic SSH anormal
    ssh_volumes = defaultdict(int)
    for ev in entetes:
        if ev["src_port"].lower() in ("22", "ssh") or ev["dst_port"].lower() in ("22", "ssh"):
            pair = tuple(sorted([ev["src_ip"], ev["dst_ip"]]))
            ssh_volumes[pair] += int(ev["length"])

    for (ip1, ip2), total in ssh_volumes.items():
        if total >= 2000:
            menaces.append(
                f"Trafic SSH important entre {ip1} et {ip2} (≈ {total} octets)."
            )

    return menaces or ["Aucune menace évidente détectée."]

# ============================================================
# 2) SCORE DE DANGEROSITÉ (VERSION AGRESSIVE + COULEURS)
# ============================================================

def couleur_score(score):
    """Retourne une couleur HTML selon le niveau de danger."""
    if score >= 30:
        return "#ff4d4d"   # rouge
    elif score >= 15:
        return "#ff944d"   # orange
    elif score >= 5:
        return "#ffe066"   # jaune
    else:
        return "#b3ffb3"   # vert

def calculer_scores_danger(entetes, menaces):
    """
    Score agressif :
      - +10 par SYN suspect
      - +6 par SSH anormal
      - +1 par 20 paquets envoyés
      - +1 par 3 destinations différentes
    """
    syn_counts = Counter()
    ssh_counts = Counter()
    packet_counts = Counter()
    dest_sets = defaultdict(set)

    # Volume et diversité
    for ev in entetes:
        src = ev["src_ip"]
        dst = ev["dst_ip"]
        packet_counts[src] += 1
        dest_sets[src].add(dst)

    # Menaces
    for m in menaces:
        texte = m.lower()

        if "scan http" in texte or "syn" in texte:
            match = re.search(r"depuis ([0-9\.]+)", m)
            if match:
                syn_counts[match.group(1)] += 1

        if "ssh" in texte:
            match = re.search(r"entre ([0-9\.]+) et ([0-9\.]+)", m)
            if match:
                ip1, ip2 = match.group(1), match.group(2)
                ssh_counts[ip1] += 1
                ssh_counts[ip2] += 1

    scores = {}
    toutes_ip = set(packet_counts.keys()) | set(syn_counts.keys()) | set(ssh_counts.keys())

    for ip in toutes_ip:
        syn = syn_counts[ip]
        ssh = ssh_counts[ip]
        vol = packet_counts[ip]
        nb_dest = len(dest_sets[ip])

        volume_bonus = vol // 20
        diversite_bonus = nb_dest // 3

        score = 10 * syn + 6 * ssh + volume_bonus + diversite_bonus
        scores[ip] = score

    return dict(sorted(scores.items(), key=lambda x: x[1], reverse=True))

def tracer_scores_danger(scores, save_path=None):
    if not scores:
        labels = ["Aucune IP"]
        valeurs = [0]
        couleurs = ["#b3ffb3"]
    else:
        labels = list(scores.keys())
        valeurs = list(scores.values())
        couleurs = [couleur_score(s) for s in valeurs]

    plt.figure(figsize=(10, 5))
    plt.bar(labels, valeurs, color=couleurs)
    plt.xticks(rotation=45, ha="right")
    plt.ylabel("Score de dangerosité")
    plt.title("Score de dangerosité par IP (mode agressif)")
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path)
        plt.close()
    else:
        plt.show()

def generer_table_scores_html(scores):
    if not scores:
        return "<p>Aucun score disponible.</p>"

    lignes = []
    lignes.append("<table style='width:100%; border-collapse: collapse;'>")
    lignes.append("<tr style='background:#005bea;color:white;'>"
                  "<th style='padding:8px;border:1px solid #ddd;'>IP</th>"
                  "<th style='padding:8px;border:1px solid #ddd;'>Score</th>"
                  "</tr>")

    for ip, score in scores.items():
        couleur = couleur_score(score)
        lignes.append(
            f"<tr style='background:{couleur};'>"
            f"<td style='padding:8px;border:1px solid #ddd;'>{ip}</td>"
            f"<td style='padding:8px;border:1px solid #ddd;text-align:center;'>{score}</td>"
            "</tr>"
        )

    lignes.append("</table>")
    return "".join(lignes)

# ============================================================
# 3) GRAPHIQUE : TOP 2–5 COUPLES IP LES PLUS ACTIFS
# ============================================================

def tracer_barres_couples_ip(entetes, save_path=None):
    compteur_couples = Counter((ev["src_ip"], ev["dst_ip"]) for ev in entetes)
    top = compteur_couples.most_common(5)

    if len(top) < 2:
        top = compteur_couples.most_common(len(compteur_couples))

    if not top:
        labels = ["Aucune donnée"]
        valeurs = [1]
    else:
        labels = [f"{src} → {dst}" for (src, dst), c in top]
        valeurs = [c for (src, dst), c in top]

    plt.figure(figsize=(10, 5))
    plt.barh(labels, valeurs, color="darkorange")
    plt.xlabel("Nombre de paquets")
    plt.title("Top communications IP (2 à 5 couples les plus actifs)")
    plt.tight_layout()

    if save_path:
        plt.savefig(save_path)
        plt.close()
    else:
        plt.show()

# ============================================================
# 4) RAPPORT HTML SIMPLE
# ============================================================

def generer_html_rapport(graph_scores, table_scores_html, menaces_html):
    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport d'analyse réseau</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: #f5f7fa;
            margin: 0;
        }}
        header {{
            background: linear-gradient(135deg, #005bea, #00c6fb);
            padding: 25px;
            text-align: center;
            color: white;
        }}
        .container {{
            width: 90%;
            max-width: 1100px;
            margin: 30px auto;
        }}
        .card {{
            background: white;
            padding: 20px;
            margin-bottom: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        h2 {{
            color: #005bea;
            border-left: 5px solid #00c6fb;
            padding-left: 10px;
        }}
        img {{
            max-width: 100%;
            border-radius: 8px;
            border: 1px solid #ccc;
        }}
        .menaces li {{
            background: #ffecec;
            border-left: 5px solid #ff4d4d;
            padding: 10px;
            margin-bottom: 10px;
            border-radius: 5px;
            list-style: none;
        }}
        footer {{
            text-align: center;
            padding: 15px;
            background: #e9eef5;
            margin-top: 30px;
        }}
    </style>
</head>
<body>

<header>
    <h1>Rapport d'analyse réseau</h1>
</header>

<div class="container">

    <div class="card">
        <h2>🔥 Score de dangerosité par IP</h2>
        <img src="{os.path.basename(graph_scores)}">
        <h2>Tableau des scores</h2>
        {table_scores_html}
    </div>

    <div class="card">
        <h2>🚨 Détail des menaces détectées</h2>
        <ul class="menaces">
            {menaces_html}
        </ul>
    </div>

</div>

<footer>
    Rapport généré automatiquement — Analyse réseau & sécurité
</footer>

</body>
</html>
"""

# ============================================================
# 5) LOGIQUE PRINCIPALE + TKINTER
# ============================================================

dernier_csv = None
dernieres_menaces = []
dernieres_entetes = []
derniers_scores = {}

def choisir_fichier():
    global dernier_csv, dernieres_menaces, dernieres_entetes, derniers_scores

    chemin = filedialog.askopenfilename(
        title="Sélectionner un fichier dump",
        filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
    )
    if not chemin:
        return

    label_chemin.config(text=f"Fichier sélectionné : {chemin}")

    try:
        with open(chemin, "r", encoding="utf-8") as f:
            lignes = f.read().splitlines()

        entetes = []
        for ligne in lignes:
            match = pattern.search(ligne)
            if match:
                d = match.groupdict()
                src_ip, src_port = split_ip_port(d["src"])
                dst_ip, dst_port = split_ip_port(d["dst"])

                entetes.append({
                    "time": d["time"],
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "flags": d["flags"],
                    "length": d["length"],
                })

        dernieres_entetes = entetes

        if not entetes:
            messagebox.showwarning("Erreur", "Aucune trame IP trouvée.")
            return

        chemin_csv = filedialog.asksaveasfilename(
            title="Enregistrer CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")]
        )
        if not chemin_csv:
            return

        with open(chemin_csv, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=entetes[0].keys(), delimiter=";")
            writer.writeheader()
            writer.writerows(entetes)

        dernier_csv = chemin_csv

        zone_texte.delete("1.0", tk.END)
        for ev in entetes:
            zone_texte.insert(
                tk.END,
                f"{ev['time']} | {ev['src_ip']}:{ev['src_port']} → "
                f"{ev['dst_ip']}:{ev['dst_port']} | Flags={ev['flags']} | Len={ev['length']}\n"
            )

        # Analyse des menaces + scores
        dernieres_menaces = analyser_menaces(entetes)
        derniers_scores = calculer_scores_danger(entetes, dernieres_menaces)

        zone_menaces.config(state="normal")
        zone_menaces.delete("1.0", tk.END)
        for m in dernieres_menaces:
            zone_menaces.insert(tk.END, f"- {m}\n")
        zone_menaces.config(state="disabled")

        messagebox.showinfo("Succès", "Analyse terminée, CSV et scores générés.")

    except Exception as e:
        messagebox.showerror("Erreur", str(e))

def afficher_ip_suspectes():
    if not dernieres_entetes:
        messagebox.showwarning("Erreur", "Aucune donnée disponible.")
        return
    tracer_barres_couples_ip(dernieres_entetes)

def exporter_rapport_html():
    if not derniers_scores:
        messagebox.showwarning("Erreur", "Aucun score disponible. Lancez d'abord une analyse.")
        return

    chemin_html = filedialog.asksaveasfilename(
        title="Enregistrer rapport HTML",
        defaultextension=".html",
        filetypes=[("HTML", "*.html")]
    )
    if not chemin_html:
        return

    dossier = os.path.dirname(chemin_html)
    graph_scores = os.path.join(dossier, "graph_scores_danger.png")

    tracer_scores_danger(derniers_scores, save_path=graph_scores)

    table_scores_html = generer_table_scores_html(derniers_scores)
    menaces_html = "".join(f"<li>{m}</li>" for m in dernieres_menaces)

    html = generer_html_rapport(graph_scores, table_scores_html, menaces_html)

    with open(chemin_html, "w", encoding="utf-8") as f:
        f.write(html)

    if messagebox.askyesno("Ouvrir", "Ouvrir le rapport dans le navigateur ?"):
        webbrowser.open_new_tab(f"file://{chemin_html}")

# ============================================================
# 6) INTERFACE TKINTER
# ============================================================

fenetre = tk.Tk()
fenetre.title("Analyse Dump Réseau — Scores & Menaces")
fenetre.geometry("900x800")

tk.Button(fenetre, text="Choisir un fichier dump", command=choisir_fichier).pack(pady=10)
tk.Button(fenetre, text="IP suspectes (couples IP)", command=afficher_ip_suspectes).pack(pady=5)
tk.Button(fenetre, text="Exporter rapport HTML (scores)", command=exporter_rapport_html).pack(pady=5)

label_chemin = tk.Label(fenetre, text="Aucun fichier sélectionné")
label_chemin.pack(pady=5)

zone_texte = tk.Text(fenetre, wrap="word", height=18)
zone_texte.pack(padx=10, pady=10, fill="both", expand=True)

tk.Label(fenetre, text="Analyse des menaces :").pack()
zone_menaces = tk.Text(fenetre, wrap="word", height=8, state="disabled", bg="#f0f0f0")
zone_menaces.pack(padx=10, pady=5, fill="x")

tk.Button(fenetre, text="Quitter", command=fenetre.destroy).pack(pady=10)

fenetre.mainloop()
