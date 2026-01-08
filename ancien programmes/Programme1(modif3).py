import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime
import csv
import os

def convertir_date(date_str):
    #Convertit une date ICS en format lisible.
    try:
        dt = datetime.strptime(date_str, "%Y%m%dT%H%M%SZ")
        return dt.strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return date_str

def choisir_fichier():
    #Ouvre un fichier ICS, lit et exporte les événements en CSV.
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier ICS",
        filetypes=[("Fichiers ICS", "*.ics"), ("Tous les fichiers", "*.*")]
    )
    
    if not chemin_fichier:
        label_chemin.config(text="Aucun fichier sélectionné")
        return
    
    label_chemin.config(text=f"Fichier sélectionné : {chemin_fichier}")
    
    try:
        with open(chemin_fichier, "r", encoding="utf-8") as f:
            lignes = f.read().splitlines()

        evenements = []
        evenement = {}

        for ligne in lignes:
            if ligne.startswith("BEGIN:VEVENT"):
                evenement = {}
            elif ligne.startswith("DTSTART:"):
                evenement["Début"] = convertir_date(ligne.replace("DTSTART:", ""))
            elif ligne.startswith("DTEND:"):
                evenement["Fin"] = convertir_date(ligne.replace("DTEND:", ""))
            elif ligne.startswith("SUMMARY:"):
                evenement["Résumé"] = ligne.replace("SUMMARY:", "").strip()
            elif ligne.startswith("LOCATION:"):
                evenement["Lieu"] = ligne.replace("LOCATION:", "").strip()
            elif ligne.startswith("DESCRIPTION:"):
                evenement["Description"] = ligne.replace("DESCRIPTION:", "").replace("\\n", " ").strip()
            elif ligne.startswith("END:VEVENT"):
                evenements.append(evenement)

        if not evenements:
            messagebox.showwarning("Aucun événement", "Aucun événement trouvé dans ce fichier.")
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
        with open(chemin_csv, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=["Début", "Fin", "Résumé", "Lieu", "Description"],delimiter=";")
            writer.writeheader()
            writer.writerows(evenements)

        messagebox.showinfo("Succès", f"Export terminé :\n{chemin_csv}")

        # Affichage dans la zone de texte
        zone_texte.delete("1.0", tk.END)
        for ev in evenements:
            zone_texte.insert(tk.END, f"{ev['Début']} → {ev['Fin']} | {ev['Résumé']} | {ev['Lieu']} | {ev['Description']}\n")

    except Exception as e:
        messagebox.showerror("Erreur", f"Impossible de traiter le fichier : {e}")

def quitter():
    #Ferme la fenêtre.
    fenetre.destroy()

# Création de la fenêtre principale
fenetre = tk.Tk()
fenetre.title("Lecture ICS et export CSV")
fenetre.geometry("800x500")

# Bouton pour choisir un fichier
btn_choisir_fichier = tk.Button(fenetre, text="Choisir un fichier ICS", command=choisir_fichier)
btn_choisir_fichier.pack(pady=10)

# Label pour afficher le chemin du fichier
label_chemin = tk.Label(fenetre, text="Aucun fichier sélectionné", wraplength=780, justify="left")
label_chemin.pack(pady=5)

# Zone de texte pour afficher le contenu traité
zone_texte = tk.Text(fenetre, wrap="word", height=20)
zone_texte.pack(padx=10, pady=10, fill="both", expand=True)

# Bouton Quitter
btn_quitter = tk.Button(fenetre, text="Quitter", command=quitter)
btn_quitter.pack(pady=10)

# Lancer l'application
fenetre.mainloop()
