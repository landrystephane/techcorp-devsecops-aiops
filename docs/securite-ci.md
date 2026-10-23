# Sécurité du pipeline — Mission A5

## 1. Les secrets GitHub Actions

Un secret (clé d'API, mot de passe) ne doit jamais être écrit dans le dépôt.
On le stocke dans **Settings → Secrets and variables → Actions**, puis on l'utilise ainsi :

    env:
      API_KEY: ${{ secrets.API_KEY }}

- Il est **chiffré** par GitHub et n'est plus lisible après sa création, même par l'administrateur.
- Il est **injecté au moment de l'exécution** du job, puis disparaît avec la machine.
- Sa valeur est **masquée** (`***`) dans les journaux.
- Il n'est **pas transmis** aux workflows déclenchés par une PR venant d'un *fork*.
- On peut le restreindre à un **environnement** (ex. `production`) soumis à approbation.

**Limites :** le masquage ne reconnaît que la valeur exacte (une version encodée en base64
s'afficherait en clair), et toute personne capable de modifier un workflow dans le dépôt
peut faire fuiter un secret. D'où l'intérêt de protéger `main` et de relire les changements
de `.github/workflows/`. Pour le cloud, on préfère des identités temporaires **OIDC**
à des clés permanentes stockées en secret.

Dans ce projet, aucun secret n'est nécessaire : Gitleaks et Trivy n'utilisent que le
`GITHUB_TOKEN` fourni automatiquement.

## 2. Le GITHUB_TOKEN et les permissions minimales

GitHub crée automatiquement un jeton `GITHUB_TOKEN` pour chaque job :
- valable **uniquement pour ce dépôt** ;
- **expire à la fin du job** ;
- ses droits sont fixés par le bloc `permissions`.

Appliqué dans `ci.yml` :

| Où | Permission | Pourquoi |
|---|---|---|
| Tout le workflow | `contents: read` | Lire le code, rien d'autre |
| Job Gitleaks uniquement | `+ pull-requests: read` | Lister les commits d'une PR |
| Aucun job | droits d'écriture | Le pipeline ne modifie rien |

Complément : `persist-credentials: false` sur chaque `checkout`, pour que le jeton
ne reste pas enregistré dans `.git/config` à disposition des étapes suivantes.

Si ce jeton fuitait malgré tout, il ne permettrait que de **lire** un dépôt public,
pendant quelques minutes.

## 3. Pourquoi un Kubernetes Secret n'est pas un coffre-fort complet

Un objet `Secret` de Kubernetes :
- est seulement **encodé en base64**, ce qui n'est pas un chiffrement :
  `echo <valeur> | base64 -d` le révèle ;
- est stocké dans **etcd**, la base de Kubernetes, **non chiffrée par défaut** :
  le chiffrement au repos doit être configuré explicitement (`EncryptionConfiguration`, KMS) ;
- est lisible par toute personne ayant le droit `get secrets` dans le *namespace*,
  ou pouvant y créer un pod qui le monte ;
- n'offre **ni rotation automatique, ni secrets temporaires, ni journal d'accès détaillé**.

Un vrai coffre-fort comme **HashiCorp Vault** apporte :
chiffrement systématique, politiques d'accès fines, journal d'audit de chaque lecture,
**secrets dynamiques** à durée de vie courte, rotation et révocation.

Bonne pratique : activer le chiffrement d'etcd, limiter le RBAC, et alimenter Kubernetes
depuis Vault (External Secrets Operator ou Secrets Store CSI Driver).

## 4. Leçon de la démonstration A4

Le marqueur fictif a été détecté par Gitleaks et la PR a été bloquée par le quality gate.
Pour le retirer, **un commit de suppression ne suffit pas** : le secret resterait dans
l'historique Git. Le commit a été retiré de la branche (`git reset` puis `git push --force`).

Avec un **vrai** secret, ce ne serait pas suffisant : dès qu'il a été poussé, il doit être
considéré comme **compromis**. Copies locales, forks, caches et liens directs vers l'ancien
commit peuvent subsister. La seule réponse fiable est de le **révoquer et de le remplacer**.