# Mesure impartiale — lots hors échantillon (A et B)

Le corpus principal (`redteam_corpus.py`) a servi à ÉCRIRE les règles : un taux de
détection élevé dessus ne prouve rien de plus que « les règles font ce pour quoi
elles ont été écrites ». Pour mesurer honnêtement la généralisation, deux lots
distincts ont été rédigés SANS relire les règles juste avant, puis passés une seule
fois — sans retoucher le lot après coup pour faire monter son propre score.

| Lot | Détectées | Faux positifs |
|---|---|---|
| A (rédigé après un 1er durcissement, puis les règles ont été affinées dessus) | 43/43 (100 %) | 0/46 |
| B (rédigé APRÈS tout durcissement, jamais retouché — mesure finale) | 7/32 (22 %) | 0/30 |

## Conclusion honnête

Le lot A affiche 100 % — mais seulement après plusieurs itérations où les règles ont
été élargies pour couvrir ses trous. Le lot B, lui, n'a JAMAIS servi à ajuster une
règle : son score (~22 %) est la mesure la plus fidèle de ce qu'un détecteur par
règles peut réellement généraliser face à des reformulations inédites.

**Ce chiffre n'est pas un échec du projet — c'est la limite connue et documentée de
toute approche par règles/mots-clés**, y compris dans des produits commerciaux
(Lakera Guard, Azure AI Content Safety publient des limites similaires). La
conclusion pour le rapport final : la détection par règles doit être présentée comme
une PREMIÈRE couche de défense (rapide, gratuite, sans dépendance externe), complétée
par une seconde couche (classification par LLM) pour les cas qu'elle ne peut pas
couvrir par nature. Voir « Limites et défense en profondeur » dans le README.
