# Rapport d'analyse réseau

## Informations générales
- Nombre total de trames analysées : **10766**
- Nombre total d'adresses IP distinctes : **37**
- Nombre de menaces détectées : **2**

## Menaces détectées
- Suspicion de scan HTTP : 2000 paquets SYN depuis 190-0-175-100.gba.solunet.com.ar vers 184.107.43.74.
- Trafic SSH important entre 192.168.190.130 et BP-Linux8 (≈ 6188 octets).

## Top IP par score de dangerosité
| IP | Score |
| --- | --- |
| `BP-Linux8` | **159** |
| `www.aggloroanne.fr` | **106** |
| `190-0-175-100.gba.solunet.com.ar` | **100** |
| `mauves.univ-st-etienne.fr` | **84** |
| `par10s38-in-f3.1e100.net` | **41** |
| `par21s23-in-f3.1e100.net` | **12** |
| `par21s04-in-f4.1e100.net` | **11** |
| `190` | **10** |
| `par21s17-in-f1.1e100.net` | **9** |
| `par21s23-in-f10.1e100.net` | **4** |
| `192.168.190.130` | **3** |
| `par21s20-in-f14.1e100.net` | **2** |
| `par21s17-in-f14.1e100.net` | **2** |
| `par21s05-in-f131.1e100.net` | **1** |
| `par21s11-in-f14.1e100.net` | **1** |
| `par10s40-in-f3.1e100.net` | **1** |
| `91.121.37.244` | **1** |
| `par21s11-in-f10.1e100.net` | **1** |
| `par21s22-in-f14.1e100.net` | **0** |
| `par10s28-in-f14.1e100.net` | **0** |

## Formule du score de dangerosité
Le score de dangerosité est calculé à partir de plusieurs composantes :
- `syn` : nombre de suspicions de scan HTTP (SYN sur port 80) pour l'IP
- `ssh` : nombre d'alertes de trafic SSH important pour l'IP
- `volume_bonus` : bonus basé sur le nombre total de paquets envoyés par l'IP
- `diversite_bonus` : bonus basé sur le nombre de destinations distinctes contactées

La formule utilisée est :
```text
score = 10 * syn + 6 * ssh + volume_bonus + diversite_bonus
```

## Commandes si problème avec Matplotlib
Si la ligne `import matplotlib.pyplot as plt` provoque une erreur (par exemple `ModuleNotFoundError: No module named 'matplotlib'`), installer ou mettre à jour Matplotlib avec la commande suivante dans un terminal :
```bash
python -m pip install matplotlib
```
Sur certains systèmes (Linux/Mac), la commande suivante peut être nécessaire :
```bash
python3 -m pip install matplotlib
```

## Visualisation du Markdown dans VS Code
Pour visualiser correctement ce fichier `.md` dans Visual Studio Code, il est recommandé d'utiliser une extension de visualisation Markdown, par exemple **Simply Markdown Viewer** (extension VS Code).
Dans VS Code :
- Ouvrir l'onglet **Extensions** (Ctrl+Shift+X)
- Rechercher `Simply Markdown Viewer`
- Installer l'extension puis ouvrir ce fichier Markdown pour obtenir un rendu lisible.
