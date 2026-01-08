import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime

def convertir_date(date_str):
    #Convertit une date ICS en format lisible.
    try:
        # Format ICS : YYYYMMDDTHHMMSSZ
        dt = datetime.strptime(date_str, "%Y%m%dT%H%M%SZ")
        return dt.strftime("%d/%m/%Y %H:%M")
    except ValueError:
        return date_str  # Si le format ne correspond pas

def choisir_fichier():
    #Ouvre un fichier ICS, lit et affiche tous les événements.
    chemin_fichier = filedialog.askopenfilename(
        title="Sélectionner un fichier ICS",
        filetypes=[("Fichiers ICS", "*.ics"), ("Tous les fichiers", "*.*")]
    )
    
    if chemin_fichier:
        label_chemin.config(text=f"Fichier sélectionné : {chemin_fichier}")
        try:
            with open(chemin_fichier, "r", encoding="utf-8") as f:
                lignes = f.read().splitlines()

            zone_texte.delete("1.0", tk.END)  # Nettoyer l'affichage
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
                    # Afficher l'événement formaté
                    zone_texte.insert(tk.END, f" {evenement.get('Début', '')} → {evenement.get('Fin', '')}\n")
                    zone_texte.insert(tk.END, f"   {evenement.get('Résumé', '')}\n")
                    zone_texte.insert(tk.END, f"   Lieu : {evenement.get('Lieu', '')}\n")
                    zone_texte.insert(tk.END, f"   {evenement.get('Description', '')}\n")
                    zone_texte.insert(tk.END, "-"*50 + "\n")

        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de lire le fichier : {e}")
    else:
        label_chemin.config(text="Aucun fichier sélectionné")

def quitter():
    #Ferme la fenêtre.
    fenetre.destroy()

# Création de la fenêtre principale
fenetre = tk.Tk()
fenetre.title("Lecture et tri d'un fichier ICS")
fenetre.geometry("700x500")

# Bouton pour choisir un fichier
btn_choisir_fichier = tk.Button(fenetre, text="Choisir un fichier", command=choisir_fichier)
btn_choisir_fichier.pack(pady=10)

# Label pour afficher le chemin du fichier
label_chemin = tk.Label(fenetre, text="Aucun fichier sélectionné", wraplength=680, justify="left")
label_chemin.pack(pady=5)

# Zone de texte pour afficher le contenu traité
zone_texte = tk.Text(fenetre, wrap="word", height=20)
zone_texte.pack(padx=10, pady=10, fill="both", expand=True)

# Bouton Quitter
btn_quitter = tk.Button(fenetre, text="Quitter", command=quitter)
btn_quitter.pack(pady=10)

# Lancer l'application
fenetre.mainloop()
