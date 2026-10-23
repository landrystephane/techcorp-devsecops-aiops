# Quality gate — TECHCORP Orders API

Le job `Quality gate` du workflow `TECHCORP Security CI` donne le verdict final.
Il est déclaré comme contrôle obligatoire : une PR ne peut pas être fusionnée sur `main` s'il est rouge.

## Ce qui bloque automatiquement la PR

| Contrôle | Outil | Bloque si… |
|---|---|---|
| Tests | Pytest | Un test échoue |
| Secrets | Gitleaks | Un secret est détecté dans le code ou l'historique Git |
| Dépendances | Trivy `fs` | Vulnérabilité **HIGH ou CRITICAL avec correctif disponible** |
| Image | Trivy `image` | Vulnérabilité **HIGH ou CRITICAL avec correctif disponible** (système et paquets Python) |

Ne bloquent pas, mais sont visibles dans les journaux : les vulnérabilités LOW/MEDIUM
et celles **sans correctif** (`ignore-unfixed`), revues lors de la revue de sécurité mensuelle.

## Trois catégories de résultats

**1. Vulnérabilité exploitable ou corrigeable → on corrige.**
Règle par défaut : si un correctif existe, on met à jour, même si la faille ne semble pas
exploitable aujourd'hui (le code peut évoluer).

**2. Faux positif → on le prouve, puis on l'ignore précisément.**
Exemple : Gitleaks signale une valeur fictive de test. On ajoute son empreinte (*fingerprint*)
dans `.gitleaksignore`, jamais une règle large qui désactiverait la détection.

**3. Exception approuvée → réservée au cas sans correctif compatible.**
Ajout dans `.trivyignore` avec un commentaire obligatoire :

    # CVE-AAAA-NNNNN — justification : <pourquoi non exploitable>
    # Approuvé par : <responsable sécurité> — Expire le : <date, 90 jours max>
    CVE-AAAA-NNNNN

Une exception sans approbation ni date d'expiration est refusée en revue de PR.

## Décisions du 23/10/2026 (premier scan de l'image)

| CVE | Paquet | Exploitable ? | Décision |
|---|---|---|---|
| CVE-2025-62727 | starlette 0.46.2 | Non (pas de `FileResponse`) | Corrigé : starlette 1.7.0 |
| CVE-2026-48818 | starlette 0.46.2 | Non (pas de `StaticFiles`, conteneur Linux) | Corrigé : starlette 1.7.0 |
| CVE-2026-54283 | starlette 0.46.2 | Non (pas de formulaire) | Corrigé : starlette 1.7.0 |
| CVE-2026-23949 | jaraco.context 5.3.0 (vendoré dans setuptools) | Non (outil d'installation) | Supprimé : `pip uninstall setuptools` |
| CVE-2026-24049 | wheel 0.45.1 (vendoré dans setuptools) | Non (outil d'installation) | Supprimé : `pip uninstall setuptools` |

Aucune exception n'a été nécessaire.