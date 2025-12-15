import tkinter as tk
from tkinter import filedialog, messagebox
import csv
import re

# Regex pour extraire les infos des entêtes IP
pattern = re.compile(
    r'(?P<time>\d{2}:\d{2}:\d{2}\.\d+)\s+IP\s+(?P<src>[^\s]+)\s+>\s+(?P<dst>[^\s]+):\s+Flags\s+\[(?P<flags>[^\]]+)\],\s+seq\s+(?P<seq>[0-9:]+),\s+ack\s+(?P<ack>\d+),\s+win\s+(?P<win>\d+).*length\s+(?P<length>\d+)')

def choisir_fichier():
    # Ouvre un fichier dump réseau, lit et exporte les entêtes en CSV
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
                entetes.append(match.groupdict())

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
                fieldnames=["time", "src", "dst", "flags", "seq", "ack", "win", "length"],
                delimiter=";"
            )
            writer.writeheader()
            writer.writerows(entetes)

        messagebox.showinfo("Succès", f"Export terminé :\n{chemin_csv}")

        # Affichage dans la zone de texte
        zone_texte.delete("1.0", tk.END)
        for ev in entetes:
            zone_texte.insert(
                tk.END,
                f"{ev['time']} | {ev['src']} → {ev['dst']} | Flags={ev['flags']} | Seq={ev['seq']} | Ack={ev['ack']} | Win={ev['win']} | Len={ev['length']}\n"
            )

    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de traiter le fichier : {e}")

def quitter():
    fenetre.destroy()

# Création de la fenêtre principale
fenetre = tk.Tk()
fenetre.title("Lecture Dump Réseau et export CSV")
fenetre.geometry("900x500")

btn_choisir_fichier = tk.Button(fenetre, text="Choisir un fichier dump", command=choisir_fichier)
btn_choisir_fichier.pack(pady=10)

label_chemin = tk.Label(fenetre, text="Aucun fichier sélectionné", wraplength=880, justify="left")
label_chemin.pack(pady=5)

zone_texte = tk.Text(fenetre, wrap="word", height=20)
zone_texte.pack(padx=10, pady=10, fill="both", expand=True)

btn_quitter = tk.Button(fenetre, text="Quitter", command=quitter)
btn_quitter.pack(pady=10)

fenetre.mainloop()
