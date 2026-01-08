import tkinter as tk
from tkinter import filedialog, messagebox
import csv
import re
from collections import Counter, defaultdict

# Regex pour extraire les infos principales d'une ligne tcpdump IP
pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+'
    r'(?P<src>[^ ]+)\s+>\s+(?P<dst>[^:]+):'
    r'.*Flags\s+\[(?P<flags>[^\]]+)\].*length\s+(?P<length>\d+)'
)

def split_ip_port(field):
    """
    Sépare "<ip>.<port>" ou "<host>.<service>" en (ip/host, port/service).
    Ex :
      "192.168.190.130.50245" -> ("192.168.190.130", "50245")
      "BP-Linux8.ssh"         -> ("BP-Linux8", "ssh")
    """
    parts = field.rsplit('.', 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    else:
        return field, ""

def analyser_menaces(entetes):
    """
    Analyse très simple pour repérer des activités suspectes.
    Retourne une liste de chaînes décrivant les menaces trouvées,
    ou une liste avec un seul message si rien de suspect.
    """
    menaces = []

    # 1) Rafale de SYN HTTP depuis une même IP vers une même cible
    # On compte les paquets avec flags == 'S' et dst_port == 'http' (ou 80)
    syn_http_counts = Counter()
    for ev in entetes:
        dst_port = ev["dst_port"].lower()
        if ev["flags"] == "S" and (dst_port == "http" or dst_port == "80"):
            cle = (ev["src_ip"], ev["dst_ip"])
            syn_http_counts[cle] += 1

    for (src_ip, dst_ip), nb in syn_http_counts.items():
        if nb >= 10:  # seuil arbitraire, tu peux le changer
            menaces.append(
                f"Suspicion de scan / attaque HTTP : {nb} paquets SYN depuis {src_ip} vers {dst_ip} (port http)."
            )

    # 2) Volume important de trafic SSH entre deux hôtes
    # On somme la longueur des paquets quand src/dst_port == ssh ou 22
    ssh_volumes = defaultdict(int)
    for ev in entetes:
        sp = ev["src_port"].lower()
        dp = ev["dst_port"].lower()
        if sp in ("ssh", "22") or dp in ("ssh", "22"):
            cle = tuple(sorted([ev["src_ip"], ev["dst_ip"]]))
            ssh_volumes[cle] += int(ev["length"])

    for (ip1, ip2), total_len in ssh_volumes.items():
        if total_len >= 2000:  # seuil arbitraire, à ajuster
            menaces.append(
                f"Trafic SSH important entre {ip1} et {ip2} (volume total ≈ {total_len} octets)."
            )

    if not menaces:
        menaces.append("Aucune menace évidente détectée selon les règles simples configurées.")

    return menaces

def choisir_fichier():
    # Sélection du fichier dump
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier dump",
        filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")]
    )

    if not chemin_fichier:
        label_chemin.config(text="Aucun fichier sélectionné")
        return

    label_chemin.config(text=f"Fichier sélectionné : {chemin_fichier}")

    try:
        with open(chemin_fichier, "r", encoding="utf-8") as f:
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

        if not entetes:
            messagebox.showwarning("Aucune trame", "Aucune entête IP trouvée dans ce fichier.")
            return

        # Demander où sauvegarder le CSV
        chemin_csv = filedialog.asksaveasfilename(
            title="Enregistrer le fichier CSV",
            defaultextension=".csv",
            filetypes=[("Fichier CSV", "*.csv")]
        )

        if not chemin_csv:
            return

        # Écriture du CSV
        with open(chemin_csv, "w", newline="", encoding="utf-8-sig") as csvfile:
            writer = csv.DictWriter(
                csvfile,
                fieldnames=["time", "src_ip", "src_port", "dst_ip", "dst_port", "flags", "length"],
                delimiter=";"
            )
            writer.writeheader()
            writer.writerows(entetes)

        messagebox.showinfo("Succès", f"Export terminé :\n{chemin_csv}")

        # Affichage des trames dans la zone de texte
        zone_texte.delete("1.0", tk.END)
        for ev in entetes:
            zone_texte.insert(
                tk.END,
                f"{ev['time']} | "
                f"{ev['src_ip']}:{ev['src_port']} → {ev['dst_ip']}:{ev['dst_port']} | "
                f"Flags={ev['flags']} | Len={ev['length']}\n"
            )

        # Analyse des menaces
        resultats = analyser_menaces(entetes)

        zone_menaces.config(state="normal")
        zone_menaces.delete("1.0", tk.END)
        zone_menaces.insert(tk.END, "Analyse des menaces potentielles :\n\n")
        for ligne in resultats:
            zone_menaces.insert(tk.END, "- " + ligne + "\n")
        zone_menaces.config(state="disabled")

    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de traiter le fichier : {e}")

def quitter():
    fenetre.destroy()

# Création de la fenêtre principale
fenetre = tk.Tk()
fenetre.title("Lecture Dump Réseau, export CSV et analyse")
fenetre.geometry("900x650")

btn_choisir_fichier = tk.Button(fenetre, text="Choisir un fichier dump", command=choisir_fichier)
btn_choisir_fichier.pack(pady=10)

label_chemin = tk.Label(fenetre, text="Aucun fichier sélectionné", wraplength=880, justify="left")
label_chemin.pack(pady=5)

zone_texte = tk.Text(fenetre, wrap="word", height=18)
zone_texte.pack(padx=10, pady=10, fill="both", expand=True)

label_menaces = tk.Label(fenetre, text="Résultats de l'analyse :")
label_menaces.pack(pady=(5, 0))

zone_menaces = tk.Text(fenetre, wrap="word", height=8, state="disabled", bg="#f0f0f0")
zone_menaces.pack(padx=10, pady=5, fill="x")

btn_quitter = tk.Button(fenetre, text="Quitter", command=quitter)
btn_quitter.pack(pady=10)

fenetre.mainloop()
