# Cahier des charges fonctionnel — AI Firewall & Compliance

**Projet INF4173** | Phase 1 — Semaine 3 | Équipe : [Étudiant 1] & [Étudiant 2]

## 1. Contexte

Les entreprises qui déploient des outils d'IA générative manquent d'un mécanisme centralisé pour
sécuriser et auditer les flux de données échangés avec les modèles d'IA. Le projet vise à livrer un
proxy applicatif — l'**AI Firewall & Compliance** — qui s'interpose entre les systèmes internes d'une
entreprise et les API de modèles de langage (LLM) compatibles OpenAI et Anthropic.

## 2. Exigences réglementaires de référence

| Source | Exigence | Impact sur le système |
|---|---|---|
| EU AI Act, Art. 12 | Enregistrement automatique et inviolable des événements sur tout le cycle de vie | Journal d'audit append-only, horodaté, avec empreinte cryptographique (hash chaîné) |
| EU AI Act, Art. 12(2) | Les logs doivent servir 3 fins : détection de risque, surveillance post-commercialisation, suivi opérationnel | Chaque entrée de log classée par type d'événement (bloqué, PII détectée, injection détectée, autorisé) |
| EU AI Act, Art. 19/26 | Conservation des logs ≥ 6 mois | Politique de rétention configurable, minimum 6 mois par défaut |
| NIST AI RMF (Govern/Map/Measure/Manage) | Gouvernance continue du risque IA | Tableau de bord permettant de suivre (Measure) et d'agir (Manage) sur les alertes en continu |
| NIST AI 600-1 (profil IA générative) | Risques spécifiques aux LLM (prompt injection, fuite de données) | Moteur de détection dédié à ces deux classes de risque |

## 3. Exigences fonctionnelles

### RF-1 — Interception des requêtes/réponses
Le système doit intercepter, en tant que proxy inverse, toute requête HTTP envoyée vers une API de
LLM compatible OpenAI ou Anthropic, ainsi que la réponse retournée, sans rupture de service pour
l'application appelante.

### RF-2 — Détection et assainissement des données sensibles (PII)
Le système doit analyser le contenu des requêtes et réponses pour détecter des catégories de données
personnelles ou sensibles (noms, courriels, numéros de carte, etc.) et, selon la politique configurée,
les masquer ou bloquer la requête.

### RF-3 — Détection des attaques par prompt injection / jailbreak
Le système doit identifier les tentatives de contournement des instructions du modèle par filtrage
d'intentions (mots-clés, patrons suspects, score de risque).

### RF-4 — Journal d'audit infalsifiable
Chaque événement (requête autorisée, bloquée, PII masquée, injection détectée) doit être journalisé
avec : horodatage, identifiant de requête, type d'événement, verdict, empreinte cryptographique liée
à l'entrée précédente (chaîne de hachage).

### RF-5 — Tableau de bord d'administration
Interface web affichant les statistiques en temps réel (requêtes totales, bloquées, alertes par type)
et la liste des événements récents.

## 4. Exigences non fonctionnelles

- **Latence** : le proxy ne doit pas ajouter plus de 50 ms de latence par rapport à un appel direct à l'API du LLM.
- **Disponibilité** : le proxy ne doit pas devenir un point de défaillance unique bloquant ; en cas d'erreur interne, un mode "fail-open" ou "fail-closed" doit être configurable.
- **Portabilité** : le système doit être déployable via conteneurs (Docker) sur une plateforme cloud (Render/Vercel).

## 5. Architecture proposée

```
Application cliente
        │
        ▼
 ┌─────────────────────────────┐
 │   AI Firewall (proxy)       │
 │  ┌───────────────────────┐  │
 │  │ 1. Réception requête  │  │
 │  │ 2. Détection PII      │  │
 │  │ 3. Détection injection│  │
 │  │ 4. Décision (bloquer/ │  │
 │  │    assainir/laisser)  │  │
 │  │ 5. Journalisation     │  │
 │  └───────────────────────┘  │
 └──────────────┬───────────────┘
                │ (si autorisé)
                ▼
      API LLM (OpenAI / Anthropic)
                │
                ▼
       Retour vers l'application
                │
                ▼
   Base de données (PostgreSQL) : journal d'audit, règles
                │
                ▼
      Tableau de bord (React) : alertes, statistiques
```

## 6. Technologies retenues

| Composant | Technologie |
|---|---|
| Proxy / API | Python, FastAPI |
| Détection PII | Microsoft Presidio (+ règles personnalisées) |
| Base de données | PostgreSQL |
| Tableau de bord | React |
| Déploiement (pilote) | Docker, Render ou Vercel |
| Gestion de code | GitHub |

## 7. Prochaines étapes (Phase 2, semaines 4 à 8)

1. Développer la couche d'interception (proxy de base, sans logique de détection).
2. Implémenter le moteur de règles PII.
3. Implémenter la détection prompt injection / jailbreak.
4. Implémenter le journal d'audit (hash chaîné).
5. Construire le tableau de bord d'administration.
