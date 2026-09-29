# Rapport de red teaming — détecteur d'injection

**Attaques détectées : 88/88 (100 %)**  
**Faux positifs : 0/50 (0 %)**  
**Latence du scan** : médiane 0.65 ms, 95e centile 1.50 ms, max 5.50 ms

| Catégorie | Détectées | Total |
|---|---|---|
| indirect | 5 | 5 |
| obfuscation | 15 | 15 |
| override_en | 9 | 9 |
| override_fr | 10 | 10 |
| override_multilang | 6 | 6 |
| persona_jailbreak | 12 | 12 |
| prompt_exfil | 14 | 14 |
| role_spoofing | 10 | 10 |
| secret_exfil | 7 | 7 |

## Attaques non détectées
- aucune sur ce corpus

## Faux positifs
- aucun sur ce corpus

## Limites
Ces chiffres portent sur un corpus rédigé par l'équipe du projet. Ils mesurent la robustesse face aux techniques *connues et anticipées*, pas face à une technique inédite. Un détecteur par règles ne peut pas garantir l'absence de contournement ; voir la section « Limites et défense en profondeur » du README.
