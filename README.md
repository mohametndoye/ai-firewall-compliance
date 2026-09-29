# AI Firewall & Compliance

Prototype réalisé dans le cadre du projet synthèse INF4173 (UQO), sous la supervision de
Dhaou Said. Proxy applicatif qui intercepte, filtre et journalise en temps réel les échanges
entre une entreprise et les API de modèles d'IA (OpenAI, Anthropic), avec un tableau de bord
de supervision en temps réel.

Voir `docs/cahier_des_charges.md` pour le détail des exigences et de l'architecture.

## Démarrage rapide — API (proxy)

```bash
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate sur Windows
pip install -r requirements.txt

cp .env.example .env      # aucune valeur n'est obligatoire, voir plus bas
uvicorn app.main:app --reload
```

L'API est alors disponible sur http://localhost:8000. Le fichier `.env` est chargé
automatiquement au démarrage (via `python-dotenv`) — inutile de l'exporter manuellement.
Sans clé API configurée, le proxy retourne une réponse simulée, ce qui permet de tester
tout le pipeline (détection PII, détection d'injection, journalisation) sans dépendance
externe. Par défaut, le journal d'audit est stocké dans un fichier SQLite local
(`ai_firewall.db`) ; pour utiliser PostgreSQL, définissez `DATABASE_URL` dans `.env`
(voir `docker-compose.yml`).

Le modèle de langue français requis par Presidio (`fr_core_news_sm`) est installé
automatiquement par `pip install -r requirements.txt` (inclus comme dépendance directe,
pas besoin de lancer `spacy download` séparément).

## Démarrage rapide — Tableau de bord

```bash
cd dashboard
npm install
npm run dev
```

Le tableau de bord est alors disponible sur http://localhost:5173. Il contient :
- un **badge « couches de défense »** dans l'en-tête, qui indique en direct si la 1re couche (règles) et la 2e couche (classifieur IA) sont actives ;
- un **panneau « Tester une requête »** avec 4 scénarios prêts à l'emploi (normale, avec données sensibles, injection classique, injection reformulée) — plus besoin de curl ni de Swagger pour essayer le firewall ;
- les **statistiques et le journal d'événements en direct**, rafraîchis automatiquement toutes les 3 secondes (et instantanément après chaque test envoyé depuis le panneau), avec la chaîne d'audit et son intégrité.

Il attend l'API sur http://localhost:8000 par défaut ; pour changer l'adresse, créez un
fichier `dashboard/.env` avec `VITE_API_URL=http://autre-adresse:port`.

## Tout démarrer avec Docker

```bash
cp .env.example .env      # optionnel, pour vos clés API réelles
docker compose up --build
```

Démarre le proxy (avec ses dépendances : SQLAlchemy, Presidio, spaCy/français) et une base
PostgreSQL, en attendant que la base soit prête avant de démarrer le proxy. Lancez le
tableau de bord séparément avec `npm run dev` dans `dashboard/`.

> **Note** : le build a été vérifié par relecture complète (Dockerfile, `docker-compose.yml`,
> `requirements.txt` alignés sur les dépendances réellement utilisées par le code) mais pas
> exécuté de bout en bout dans l'environnement de développement utilisé pour ce projet (accès
> réseau restreint à Docker Hub à cet endroit précis). À exécuter et valider sur votre poste —
> voir la section Dépannage ci-dessous en cas de souci.

### Dépannage Docker

- **`db` ne répond pas / le proxy plante au démarrage** : `docker compose logs db` — le
  `healthcheck` de PostgreSQL doit passer avant que le proxy démarre (`depends_on: condition:
  service_healthy`). Si ça bloque, vérifiez qu'aucun autre service n'utilise déjà le port 5432.
- **`pip install` échoue sur le modèle spaCy français** : le `requirements.txt` installe
  `fr_core_news_sm` directement depuis son wheel GitHub ; si votre réseau bloque GitHub,
  téléchargez le fichier manuellement et changez la ligne pour un chemin local.
- **Port 8000 déjà utilisé** : changez le mapping dans `docker-compose.yml` (`"8001:8000"` par
  exemple).
- **Rebuild propre après un changement** : `docker compose down -v && docker compose up --build`.

## Tester

```bash
pytest tests/ -v
```

20 tests couvrant : santé de l'API, détection PII (regex + Presidio), détection d'injection
(règles), classifieur IA (2e couche, avec appels réseau simulés), pipeline complet du proxy,
intégrité de la chaîne d'audit, endpoints d'administration.

## Essayer une requête

**Le plus simple : utilisez le panneau « Tester une requête » du tableau de bord** (voir
section précédente) — quatre scénarios prêts à cliquer, aucune commande à taper.

Alternative en ligne de commande :
```bash
curl -X POST http://localhost:8000/v1/proxy/chat \
  -H "Content-Type: application/json" \
  -d '{"provider": "openai", "model": "gpt-4", "prompt": "Bonjour, comment vas-tu ?"}'
```

Alternative via navigateur : http://localhost:8000/docs (documentation interactive
Swagger, générée automatiquement — visiter http://localhost:8000/ vous y redirige aussi).

## Déploiement

Le projet est prêt à déployer sur des services gratuits/étudiants, sans changement de code :

- **Backend (proxy)** → [Render](https://render.com). Le fichier `render.yaml` à la racine
  décrit tout (service web Python + base PostgreSQL) : sur Render, « New + » → « Blueprint »
  → sélectionner ce dépôt. Une fois créé, ajouter vos clés API dans Settings → Environment si
  vous voulez les utiliser (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, et les variables
  `AI_FIREWALL_CLASSIFIER_*` pour la 2e couche) — sinon le proxy tourne en mode simulé.
- **Tableau de bord** → [Vercel](https://vercel.com). `dashboard/vercel.json` configure déjà
  le build Vite. Importer le dépôt sur Vercel, définir le répertoire racine du projet à
  `dashboard/`, et ajouter la variable d'environnement `VITE_API_URL` pointant vers l'URL du
  backend déployé sur Render (ex. `https://ai-firewall-backend.onrender.com`).
- **Base de données** : incluse dans le `render.yaml` (PostgreSQL géré par Render).

Le CORS du proxy (`allow_origins=["*"]`) accepte déjà les requêtes depuis n'importe quel
domaine Vercel sans configuration supplémentaire — à restreindre au domaine exact du tableau
de bord si ce prototype devait dépasser le cadre du cours.

## Faut-il de vraies clés API OpenAI/Anthropic ?

Non, ce n'est pas exigé pour démontrer le pipeline : sans clé, le proxy simule la réponse du
LLM tout en exécutant réellement la détection PII, la détection d'injection, la 2e couche (si
configurée) et la journalisation — c'est-à-dire tout ce que le cahier des charges demande. Une
clé API devient utile pour deux choses précises, toutes deux optionnelles :

1. **Activer réellement la 2e couche de détection** (`app/detectors/llm_classifier.py`) : elle
   ne s'active que si `OPENAI_API_KEY` ou `ANTHROPIC_API_KEY` (ou les variables
   `AI_FIREWALL_CLASSIFIER_*` dédiées) sont renseignées. Un compte OpenAI/Anthropic avec
   quelques dollars de crédit suffit largement (le classifieur utilise un modèle économique —
   `gpt-4o-mini` ou `claude-3-5-haiku` — et un seul appel très court par requête).
2. **Mesurer la latence réelle de bout en bout** avec un vrai fournisseur en aval, plutôt que
   la réponse simulée instantanée (voir note technique plus bas).

## Structure du projet

```
app/
  main.py              # Point d'entrée FastAPI, orchestration du pipeline
  config.py            # Configuration (latence max, politique d'échec, clés API, DB, classifieur)
  db.py                # Connexion et modèles SQLAlchemy (PostgreSQL/SQLite)
  detectors/
    pii.py             # Détection PII : regex + Microsoft Presidio (modèle français)
    injection.py       # Détection prompt injection / jailbreak — 1re couche (règles)
    normalize.py       # Normalisation anti-obfuscation (homoglyphes, leet, base64, etc.)
    llm_classifier.py  # Détection d'intention par LLM — 2e couche (défense en profondeur)
  audit/
    logger.py          # Journal d'audit infalsifiable (chaîne de hachage), persisté en DB
tests/
  test_proxy.py        # Tests du pipeline complet
  test_classifier.py   # Tests du classifieur LLM (mockés, sans dépendance réseau)
  redteam_corpus.py, redteam_holdout_a.py, redteam_holdout_b.py  # Corpus de red teaming
scripts/
  redteam_report.py    # Mesure détection/faux positifs/latence sur le corpus principal
  holdout_eval.py      # Mesure sur un lot hors échantillon (a ou b)
dashboard/
  src/App.jsx          # Console de supervision React (stats + journal + badge des couches)
  src/Tester.jsx        # Panneau de test avec scénarios prêts à l'emploi
  src/console.css
  vercel.json          # Config de déploiement Vercel
docs/
  cahier_des_charges.md
  rapport_red_team.md
  mesure_impartiale_holdout.md
docker-compose.yml       # Proxy + PostgreSQL
render.yaml               # Déploiement backend sur Render (Blueprint)
```

## État d'avancement

- [x] Proxy d'interception (OpenAI/Anthropic)
- [x] Détection et assainissement PII (regex + Presidio, modèle français)
- [x] Détection prompt injection / jailbreak, 1re couche par règles (voir « Limites » ci-dessous)
- [x] Classifieur LLM en 2e couche, défense en profondeur (implémenté, s'active avec une clé API — voir « Limites »)
- [x] Journal d'audit infalsifiable, persisté (PostgreSQL/SQLite)
- [x] Tableau de bord d'administration (React, temps réel, badge des couches de défense)
- [x] Tests de pénétration (red teaming) sur le détecteur d'injection — voir `docs/rapport_red_team.md`
- [x] Fichiers de déploiement prêts (Docker, Render, Vercel — voir « Déploiement »)
- [ ] Mesure de la latence réelle ajoutée avec de vraies clés API (voir note ci-dessous)
- [ ] Déploiement pilote effectif (les fichiers sont prêts, le déploiement lui-même reste à faire par l'équipe)
- [ ] Mesure du gain réel de la 2e couche sur le lot B avec une vraie clé API (voir « Limites »)

## Limites et défense en profondeur — détection d'injection

Le détecteur 1re couche (`app/detectors/injection.py` + `normalize.py`) combine des règles
pondérées par famille d'attaque avec une normalisation anti-obfuscation (homoglyphes, texte
espacé, leet, base64/hex/ROT13, fautes de frappe). Il a été mesuré avec une méthodologie de
red teaming en trois temps, documentée dans `docs/mesure_impartiale_holdout.md` :

| Corpus | Rôle | Détection |
|---|---|---|
| `tests/redteam_corpus.py` (88 attaques) | a servi à écrire les règles | 100 % |
| `tests/redteam_holdout_a.py` (43 attaques) | vu une fois, puis les règles ont été affinées dessus | 100 % |
| `tests/redteam_holdout_b.py` (32 attaques) | **jamais vu avant d'écrire les règles, jamais retouché ensuite** | **~22 %** |

**Le chiffre qui compte, c'est celui du lot B.** Les deux premiers montrent surtout que
les règles font ce pour quoi elles ont été écrites — un score élevé dessus ne prouve pas
la généralisation. Le lot B, rédigé sans relire le code puis jamais utilisé pour ajuster
une règle, montre la vraie limite : **un détecteur par mots-clés/regex ne généralise pas
bien à des reformulations qu'il n'a pas anticipées**, même après un durcissement sérieux.

Ce n'est pas spécifique à ce projet — c'est une limite connue de toute détection par
règles (documentée aussi pour des produits commerciaux comme Lakera Guard ou Azure AI
Content Safety). Zéro faux positif a été maintenu tout au long du durcissement (aucune
règle n'a été élargie au point de bloquer des questions légitimes sur la sécurité, le
développement ou les prompts).

**Ce que la 2e couche change concrètement** : `app/detectors/llm_classifier.py` demande à un
LLM de juger l'*intention* du message (tentative de manipuler un système d'IA, oui/non) plutôt
que sa forme littérale, ce qui est précisément ce que les règles ne peuvent pas faire. Elle
s'exécute seulement quand les règles n'ont pas déjà bloqué la requête, et seulement si une clé
API est configurée — sans clé, le comportement est identique à avant (voir « Faut-il de
vraies clés API »). **Important, en toute transparence** : dans l'environnement où ce projet a
été développé, aucune clé API n'était disponible pour mesurer le gain réel de cette couche sur
le lot B. Le classifieur est testé unitairement avec des appels réseau simulés
(`tests/test_classifier.py`) et intégré dans le pipeline, mais le chiffre « la 2e couche fait
passer le lot B de 22 % à X % » reste à mesurer par l'équipe une fois une clé API configurée —
c'est un exercice de quelques minutes une fois la clé en main (relancer `pytest`, puis tester
le préréglage « Injection (reformulée) » dans le tableau de bord).

Combiner les deux couches (règles pour le blocage instantané des cas évidents et peu coûteux,
classifieur pour le jugement contextuel des reformulations) reflète l'approche de défense
en profondeur recommandée par le NIST AI RMF plutôt qu'un filtre unique — et reste honnête sur
le fait qu'aucune des deux couches, seule ou combinée, ne rend le système totalement
impossible à contourner. C'est une réduction de risque mesurée, pas une garantie.

Pour reproduire les mesures :
```bash
python scripts/redteam_report.py        # corpus principal (1re couche seule)
python scripts/holdout_eval.py a         # lot A (1re couche seule)
python scripts/holdout_eval.py b         # lot B (1re couche seule — la mesure qui compte)
```

## Note technique — latence

Lors des tests manuels, la toute première requête après le démarrage du serveur prend
environ 150-200 ms (chargement paresseux du modèle Presidio/spaCy en mémoire), alors que
les requêtes suivantes prennent 2 à 10 ms de traitement côté firewall pour la 1re couche —
bien en-deçà de l'exigence de 50 ms. La 2e couche (classifieur IA), quand elle est active,
ajoute la latence d'un appel réseau à un LLM externe (typiquement 300 à 800 ms selon le
fournisseur) : c'est le compromis attendu d'une défense en profondeur — rapide et gratuite en
première ligne, plus lente mais plus fine en seconde ligne, et seulement pour les requêtes que
la 1re couche n'a pas déjà tranchées.

Pour respecter l'exigence de latence dès la première requête en production, il faudra
précharger le modèle Presidio/spaCy au démarrage du serveur plutôt qu'au premier appel
(amélioration à faire en Phase 3, lors du réglage des performances).
