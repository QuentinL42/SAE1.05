import tkinter as tk
from tkinter import filedialog, messagebox

def choisir_fichier():
    # Ouvre une boîte de dialogue pour sélectionner un fichier
    chemin_fichier = filedialog.askopenfilename(title="Sélectionner un fichier")
    
    # Affiche le chemin du fichier sélectionné
    if chemin_fichier:
        label_chemin.config(text=f"Fichier sélectionné : {chemin_fichier}")
        try:
            with open(chemin_fichier, "r", encoding="utf-8") as f:
                contenu = f.read()
            # Affiche le contenu dans la zone de texte
            zone_texte.delete("1.0", tk.END)
            zone_texte.insert(tk.END, contenu)
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de lire le fichier : {e}")
    else:
        label_chemin.config(text="Aucun fichier sélectionné")

def quitter():
    #Ferme la fenêtre principale proprement.
    fenetre.destroy()

# Création de la fenêtre principale
fenetre = tk.Tk()
fenetre.title("Sélectionner et lire un fichier")
fenetre.geometry("500x400")

# Ajout d'un bouton pour ouvrir le dialogue de sélection de fichier
btn_choisir_fichier = tk.Button(fenetre, text="Choisir un fichier", command=choisir_fichier)
btn_choisir_fichier.pack(pady=10)

# Label pour afficher le chemin du fichier
label_chemin = tk.Label(fenetre, text="Aucun fichier sélectionné", wraplength=480, justify="left")
label_chemin.pack(pady=20)

# Zone de texte pour afficher le contenu du fichier
zone_texte = tk.Text(fenetre, wrap="word", height=15)
zone_texte.pack(padx=10, pady=10, fill="both", expand=True)

# Bouton Quitter
btn_quitter = tk.Button(fenetre, text="Quitter", command=quitter)
btn_quitter.pack(pady=20)




# Lancer l'interface graphique
fenetre.mainloop()

