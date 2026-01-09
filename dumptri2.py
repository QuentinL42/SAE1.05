import tkinter as tk
from tkinter import filedialog, messagebox
import csv
import re
from collections import Counter, defaultdict
import matplotlib.pyplot as plt
import os
import webbrowser
import json

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
    if score >= 30:
        return "#ff4d4d"   # rouge
    elif score >= 15:
        return "#ff944d"   # orange
    elif score >= 5:
        return "#ffe066"   # jaune
    else:
        return "#b3ffb3"   # vert

def calculer_scores_danger(entetes, menaces):
    syn_counts = Counter()
    ssh_counts = Counter()
    packet_counts = Counter()
    dest_sets = defaultdict(set)

    for ev in entetes:
        src = ev["src_ip"]
        dst = ev["dst_ip"]
        packet_counts[src] += 1
        dest_sets[src].add(dst)

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

# ============================================================
# 3) TOP N CONFIGURABLE (TKINTER)
# ============================================================

def get_top_n():
    try:
        return max(1, int(entry_topn.get()))
    except:
        return 10

# ============================================================
# 4) GRAPHIQUE LOCAL (MATPLOTLIB)
# ============================================================

def tracer_scores_danger(scores, save_path=None):
    if not scores:
        labels = ["Aucune IP"]
        valeurs = [0]
        couleurs = ["#b3ffb3"]
    else:
        N = get_top_n()
        top = list(scores.items())[:N]
        labels = [ip for ip, score in top]
        valeurs = [score for ip, score in top]
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

# ============================================================
# 5) TABLEAU HTML
# ============================================================

def generer_table_scores_html(scores):
    lignes = []
    lignes.append("<table id='scoreTable' style='width:100%; border-collapse: collapse;'>")
    lignes.append("<thead><tr style='background:#005bea;color:white;'>"
                  "<th style='padding:8px;border:1px solid #ddd;'>IP</th>"
                  "<th style='padding:8px;border:1px solid #ddd;'>Score</th>"
                  "</tr></thead><tbody>")

    for ip, score in scores.items():
        couleur = couleur_score(score)
        lignes.append(
            f"<tr class='dataRow' style='background:{couleur};'>"
            f"<td style='padding:8px;border:1px solid #ddd;color:black;'>{ip}</td>"
            f"<td style='padding:8px;border:1px solid #ddd;text-align:center;color:black;'>{score}</td>"
            "</tr>"
        )

    lignes.append("</tbody></table>")
    return "".join(lignes)

# ============================================================
# 6) RAPPORT HTML INTERACTIF (Chart.js + Mode sombre + Top N)
# ============================================================

def generer_html_rapport(scores, menaces):
    labels = list(scores.keys())
    valeurs = list(scores.values())
    labels_json = json.dumps(labels, ensure_ascii=False)
    valeurs_json = json.dumps(valeurs, ensure_ascii=False)

    table_scores_html = generer_table_scores_html(scores)
    menaces_html = "".join(f"<li>{m}</li>" for m in menaces)

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Rapport d'analyse réseau</title>
    <style>
        :root {{
            --bg-color: #f5f7fa;
            --text-color: #222222;
            --card-bg: #ffffff;
            --card-shadow: 0 2px 8px rgba(0,0,0,0.1);
            --header-bg: linear-gradient(135deg, #005bea, #00c6fb);
            --table-border: #dddddd;
            --menace-bg: #ffecec;
            --menace-border: #ff4d4d;
        }}
        body.dark {{
            --bg-color: #1e1e1e;
            --text-color: #e0e0e0;
            --card-bg: #2b2b2b;
            --card-shadow: 0 2px 8px rgba(0,0,0,0.6);
            --header-bg: linear-gradient(135deg, #141e30, #243b55);
            --table-border: #555555;
            --menace-bg: #3b1f1f;
            --menace-border: #ff6b6b;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, sans-serif;
            background: var(--bg-color);
            color: var(--text-color);
            margin: 0;
            transition: background 0.3s, color 0.3s;
        }}
        header {{
            background: var(--header-bg);
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
            background: var(--card-bg);
            padding: 20px;
            margin-bottom: 25px;
            border-radius: 10px;
            box-shadow: var(--card-shadow);
            transition: background 0.3s, box-shadow 0.3s;
        }}
        h2 {{
            color: #005bea;
            border-left: 5px solid #00c6fb;
            padding-left: 10px;
        }}
        body.dark h2 {{
            color: #66aaff;
            border-left-color: #3399ff;
        }}
        .menaces li {{
            background: var(--menace-bg);
            border-left: 5px solid var(--menace-border);
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
        body.dark footer {{
            background: #252525;
        }}
        table {{
            color: inherit;
        }}
        #scoreTable th, #scoreTable td {{
            border: 1px solid var(--table-border);
        }}
        /* Texte du tableau toujours noir pour lisibilité */
        #scoreTable td,
        #scoreTable th {{
            color: #000000 !important;
        }}
        body.dark #scoreTable td,
        body.dark #scoreTable th {{
            color: #000000 !important;
        }}
        .top-controls {{
            display: flex;
            align-items: center;
            gap: 10px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }}
        .top-controls input[type="number"] {{
            width: 70px;
            padding: 4px;
        }}
        .btn {{
            padding: 6px 12px;
            border-radius: 5px;
            border: none;
            cursor: pointer;
            background: #005bea;
            color: white;
        }}
        .btn:hover {{
            background: #0040b3;
        }}
        body.dark .btn {{
            background: #3399ff;
        }}
        body.dark .btn:hover {{
            background: #1f7ad1;
        }}
        .btn-secondary {{
            background: #666666;
        }}
        body.dark .btn-secondary {{
            background: #444444;
        }}
        .btn-secondary:hover {{
            background: #555555;
        }}
        body.dark .btn-secondary:hover {{
            background: #333333;
        }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>

<header>
    <h1>Rapport d'analyse réseau</h1>
</header>

<div class="container">

    <div class="card">
        <div class="top-controls">
            <h2 style="margin:0;">🔥 Score de dangerosité par IP</h2>
            <div>
                <label for="topN">Afficher Top N IP :</label>
                <input type="number" id="topN" value="10" min="1">
                <button class="btn" onclick="applyTopN()">Mettre à jour</button>
            </div>
            <button class="btn btn-secondary" onclick="toggleDarkMode()">Mode sombre / clair</button>
        </div>
        <canvas id="scoreChart" height="120"></canvas>

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

<script>
    const labelsAll = {labels_json};
    const scoresAll = {valeurs_json};
    let scoreChart = null;
    let isDark = false;

    function buildChart(N) {{
        const ctx = document.getElementById('scoreChart').getContext('2d');
        const labels = labelsAll.slice(0, N);
        const data = scoresAll.slice(0, N);

        const textColor = isDark ? '#e0e0e0' : '#222222';
        const gridColor = isDark ? '#555555' : '#cccccc';

        if (scoreChart) {{
            scoreChart.destroy();
        }}

        scoreChart = new Chart(ctx, {{
            type: 'bar',
            data: {{
                labels: labels,
                datasets: [{{
                    label: 'Score de dangerosité',
                    data: data,
                    backgroundColor: data.map(v => {{
                        if (v >= 30) return '#ff4d4d';
                        if (v >= 15) return '#ff944d';
                        if (v >= 5) return '#ffe066';
                        return '#b3ffb3';
                    }}),
                    borderWidth: 1
                }}]
            }},
            options: {{
                responsive: true,
                plugins: {{
                    legend: {{
                        labels: {{
                            color: textColor
                        }}
                    }},
                    tooltip: {{
                        enabled: true
                    }}
                }},
                scales: {{
                    x: {{
                        ticks: {{
                            color: textColor
                        }},
                        grid: {{
                            color: gridColor
                        }}
                    }},
                    y: {{
                        beginAtZero: true,
                        ticks: {{
                            color: textColor
                        }},
                        grid: {{
                            color: gridColor
                        }}
                    }}
                }}
            }}
        }});
    }}

    function applyTopN() {{
        let N = parseInt(document.getElementById('topN').value);
        if (isNaN(N) || N < 1) N = 10;

        const rows = document.querySelectorAll('#scoreTable tr.dataRow');
        rows.forEach((row, idx) => {{
            row.style.display = idx < N ? 'table-row' : 'none';
        }});

        buildChart(N);
    }}

    function toggleDarkMode() {{
        isDark = !isDark;
        document.body.classList.toggle('dark', isDark);
        let N = parseInt(document.getElementById('topN').value);
        if (isNaN(N) || N < 1) N = 10;
        buildChart(N);
    }}

    window.onload = function() {{
        applyTopN();
    }};
</script>

</body>
</html>
"""

# ============================================================
# 7) GRAPHIQUE : TOP 2–5 COUPLES IP LES PLUS ACTIFS
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
# 8) LOGIQUE PRINCIPALE
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

    html = generer_html_rapport(derniers_scores, dernieres_menaces)

    with open(chemin_html, "w", encoding="utf-8") as f:
        f.write(html)

    if messagebox.askyesno("Ouvrir", "Ouvrir le rapport dans le navigateur ?"):
        webbrowser.open_new_tab(f"file://{chemin_html}")

# ============================================================
# 9) INTERFACE TKINTER
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

frame_topn = tk.Frame(fenetre)
frame_topn.pack(pady=5)

tk.Label(frame_topn, text="Afficher Top N IP (graphique local) :").pack(side="left")

entry_topn = tk.Entry(frame_topn, width=5)
entry_topn.insert(0, "10")
entry_topn.pack(side="left")

tk.Button(fenetre, text="Quitter", command=fenetre.destroy).pack(pady=10)

fenetre.mainloop()
