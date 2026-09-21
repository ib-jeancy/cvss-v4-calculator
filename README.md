# Calculateur CVSS v4.0 — version française

Calculateur web du **Common Vulnerability Scoring System (CVSS) version 4.0**, entièrement traduit
en français et doté d'une interface repensée (thème sombre et clair, jauge de score animée, vecteur
partageable par lien).

Les calculs suivent le [document de spécification CVSS v4.0](https://www.first.org/cvss/v4.0/specification-document)
du FIRST, qui fait référence pour l'évaluation de la gravité des vulnérabilités.

## Fonctionnalités

- **Les 32 métriques de la spécification**, réparties en cinq onglets :
  - Métriques de base (AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA)
  - Métriques de menace (E)
  - Métriques environnementales — métriques de base modifiées (MAV … MSA)
  - Métriques environnementales — exigences de sécurité (CR, IR, AR)
  - Métriques supplémentaires (S, AU, R, V, RE, U)
- **Score et sévérité** calculés en direct, avec nomenclature CVSS-B / BT / BE / BTE.
- **Détail du macro-vecteur** (les six classes d'équivalence) pour comprendre d'où vient le score.
- **Définitions en français** de chaque métrique et de chaque valeur, au survol.
- **Vecteur partageable** : copie en un clic, synchronisation avec l'ancre de l'URL — un lien
  rouvre le calculateur avec les mêmes valeurs.
- **Thème sombre ou clair**, mémorisé dans le navigateur, et interface adaptée au mobile.

## Architecture

| Fichier | Rôle |
| --- | --- |
| `index.html` | Structure de la page et gabarit Vue 3 |
| `styles.css` | Thèmes, mise en page et composants |
| `app.js` | Couche interface : onglets, infobulles, presse-papiers, thème, jauge |
| `cvss40.js` | Moteur de calcul : classes `Vector` et `CVSS40` |
| `metrics.json` | Libellés et définitions françaises de toutes les métriques |

- La classe `Vector` gère la chaîne du vecteur et les métriques associées : mise à jour, validation,
  calcul des classes d'équivalence.
- La classe `CVSS40` s'appuie sur une instance de `Vector` pour produire le score et la sévérité.
- `metrics.json` ne pilote que l'affichage : les valeurs admissibles restent définies dans `cvss40.js`.

## Utilisation locale

```bash
python3 -m http.server 8000
# puis ouvrir http://localhost:8000
```

Un simple serveur statique suffit : `metrics.json` est chargé par `fetch`, l'ouverture directe du
fichier en `file://` est donc bloquée par le navigateur.

## Licence

Projet sous licence BSD-2-Clause. Voir le fichier [LICENSE](./LICENSE).
Moteur de calcul : copyright FIRST.ORG, Inc., Red Hat et contributeurs.
