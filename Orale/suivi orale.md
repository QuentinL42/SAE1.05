# ========== SCRIPT DÉMONSTRATION (À LANCER) ==========

"""
PRÉSENTATION ORALE SAÉ1.05 - SCRIPT DE DÉMONSTRATION

Timing :
0:00 - 1:00 → Introduction
1:00 - 2:00 → Architecture du code
2:00 - 4:00 → Démo fichier 1
4:00 - 6:00 → Rapports générés
6:00 -11:00 → Nouveau fichier en direct
11:00-12:00 → Conclusion

ACTIONS À FAIRE :
"""

# =====================================================
# ÉTAPE 1 : LANCER L'APPLICATION (0:30)
# =====================================================

# 1. Ouvrir un terminal
# 2. Naviguer vers le dossier du projet
# 3. Lancer l'app Tkinter

# $ cd /chemin/vers/projet
# $ python3 analyseur.py

# → La fenêtre Tkinter s'ouvre
# → Montrer l'interface avec les boutons

print("""
👉 RÉSULTAT ATTENDU :
   - Fenêtre Tkinter visible
   - Boutons : "Choisir un fichier dump", "IP suspectes", "Exporter HTML", etc.
   - Zone de texte et zone menaces vides (en attente)
""")

# =====================================================
# ÉTAPE 2 : CHARGER FICHIER DE TEST (2:00 - 2:30)
# =====================================================

print("""
🎬 DÉMO : Charger dump_test.txt

ACTION : Cliquer sur "Choisir un fichier dump"
         → Sélectionner dump_test.txt
         
L'application affiche :
  ✅ Trames extraites (14 trames trouvées)
  ✅ Menaces détectées :
     - Suspicion de scan HTTP : 11 paquets SYN depuis 192.168.1.10 vers 10.0.0.1
     - Trafic SSH important entre 192.168.1.11 et 10.0.0.2 (≈ 5000 octets)
  ✅ Zone menaces remplie
  ✅ Fichier CSV généré

À DIRE :
"L'application a extrait 14 trames et identifié 2 menaces principales :
- Une IP (192.168.1.10) fait un scan HTTP massif sur le port 80 (11 paquets SYN)
- Une autre IP (192.168.1.11) génère du trafic SSH anormal (5000 octets)

En temps normal, identifier cela prendrait HEURES. Ici : 2 secondes ! 🚀"
""")

# =====================================================
# ÉTAPE 3 : MONTRER RAPPORT HTML (3:00 - 4:00)
# =====================================================

print("""
📊 RAPPORT HTML INTERACTIF

ACTION : Cliquer "Exporter rapport HTML"
         → Le navigateur s'ouvre et affiche le rapport

À MONTRER et DIRE :
1. "Voici le graphique interactif. Vous voyez les IP triées par dangerosité."
   → Pointer le graphique Chart.js

2. "Les couleurs indiquent le niveau :"
   → Montrer : rouge (score ≥ 30), orange (≥ 15), jaune (≥ 5), vert (< 5)

3. "Je peux activer le mode sombre pour faciliter la lecture."
   → Cliquer le bouton "Mode sombre / clair"

4. "Et voici le tableau détaillé de toutes les IP avec leurs scores."
   → Scroller sur le tableau

5. "Enfin, les menaces détectées sont listées ici avec détail."
   → Montrer la section menaces
""")

# =====================================================
# ÉTAPE 4 : MONTRER RAPPORT MARKDOWN (4:00 - 4:30)
# =====================================================

print("""
📄 RAPPORT MARKDOWN

ACTION : Cliquer "Exporter rapport Markdown"
         → VS Code s'ouvre avec le fichier .md

À DIRE :
"Ce Markdown documente TOUT :
- Nombre de trames analysées
- Les IP distinctes
- Les menaces trouvées
- La FORMULE du score (pour que les équipes en Inde comprennent)
- Même les commandes d'installation si problème de matplotlib

Ce fichier peut être envoyé par email aux administrateurs réseau en Inde,
ils comprendront immédiatement la situation."
""")

# =====================================================
# ÉTAPE 5 : MONTRER FICHIER CSV (4:30 - 5:00)
# =====================================================

print("""
📋 FICHIER CSV (EXPLOITABLE EXCEL)

ACTION : Ouvrir le fichier CSV généré dans Excel

À DIRE :
"Ce CSV contient toutes les trames extraites :
- Timestamp
- IP source et destination
- Ports
- Flags TCP
- Taille des paquets

Les administrateurs peuvent utiliser Excel pour :
- Faire des pivot tables
- Créer des graphiques personnalisés
- Filtrer par IP, port, etc.
- Exporter en d'autres formats
"
""")

# =====================================================
# ÉTAPE 6 : TRAITER NOUVEAU FICHIER EN DIRECT (6:00 - 11:00) ✨
# =====================================================

print("""
⚡ NOUVEAU FICHIER - PRÉSENTÉ SUR PLACE

L'examinateur te donne un AUTRE fichier tcpdump.

PROCÉDURE :
1. L'application Tkinter est toujours ouverte
2. Cliquer "Choisir un fichier dump"
3. Sélectionner le nouveau fichier
4. L'app traite en 1-2 secondes
5. Commentar les résultats :

EXEMPLE DE COMMENTAIRE :
"Regardez, l'application a trouvé 5 menaces cette fois.
L'IP 172.16.0.50 a un score très élevé (score: 120).
- Elle a envoyé 8 paquets SYN sur le port 80
- Elle a 4 alertes SSH
- Elle a contacté 20 destinations différentes
- Elle a envoyé 2000 paquets

C'est clairement une activité suspecte. On devrait la bloquer."

6. Générer les rapports HTML et Markdown
7. Montrer les résultats
""")

# =====================================================
# ÉTAPE 7 : CONCLUSION (11:00 - 12:00)
# =====================================================

print("""
✅ CONCLUSION

À DIRE :
"En résumé :
✓ J'ai créé un outil qui automatise l'analyse des trames réseau
✓ Il détecte les menaces (scan HTTP, SSH anormal)
✓ Il calcule un score pour chaque IP
✓ Il génère 3 types de rapports (HTML, Markdown, CSV)
✓ Il traite les nouveaux fichiers en quelques secondes

Cet outil résout la problématique initiale :
→ Identifier les 2 activités suspectes sur le réseau en Inde
→ Permettre aux administrateurs réseau de réagir rapidement
→ Automatiser ce qui prenait des heures

Merci pour votre attention. Des questions ?"
""")

# =====================================================
# QUESTIONS POSSIBLES
# =====================================================

print("""
⚠️ QUESTIONS POSSIBLES DE L'EXAMINATEUR :

1. "Pourquoi 10 × SYN et 6 × SSH dans la formule ?"
   R: "J'ai choisi 10 car un scan HTTP est très suspect (beaucoup de tentatives).
       SSH a un poids inférieur (6) car c'est moins indicatif seul."

2. "Qu'est-ce qu'un paquet SYN ?"
   R: "C'est le premier paquet d'une connexion TCP. Beaucoup de SYN = scan/tentatives."

3. "Pourquoi Markdown et HTML ensemble ?"
   R: "HTML pour visualiser (graphiques), Markdown pour documenter (texte, formules)."

4. "Que se passe-t-il avec un format tcpdump différent ?"
   R: "Je pourrais adapter la regex pour gérer d'autres formats."

5. "Comment les équipes en Inde vont l'utiliser ?"
   R: "Notice d'utilisation en anglais + code sur GitHub. Ils lancent le script,
       sélectionnent leur fichier, et obtiennent les rapports automatiquement."
""")
