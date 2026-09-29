"""Détection des attaques par prompt injection / jailbreak.

Architecture (défense en profondeur, voir README « Limites et défense en profondeur ») :

1. Normalisation multi-vues (app.detectors.normalize) : le texte est analysé sous
   plusieurs formes (accents retirés, leet, texte espacé, rot13, inversé, hex,
   base64, fautes de frappe corrigées) pour neutraliser les contournements connus.
2. Règles pondérées, par famille d'attaque : annulation d'instructions,
   exfiltration du prompt système, jailbreak par personnage/mode, usurpation de
   rôle ou de délimiteurs, exfiltration de secrets, injection indirecte. Chaque
   règle contribue à un score ; le firewall bloque à partir de RISK_THRESHOLD.
   Les règles très explicites suffisent seules ; les signaux ambigus (ex. « mode
   développeur », qui existe aussi sur Android) ne bloquent qu'en combinaison.
3. Bonus d'obfuscation : une attaque qui n'apparaît que dans une vue « déguisée »
   (base64, rot13, leet...) reçoit un bonus — dissimuler une consigne est en soi
   un signal.

Toutes les règles sont écrites pour la forme canonique (minuscules, sans accents,
tirets internes remplacés par des espaces). Les phrases où l'utilisateur annule
SES PROPRES instructions (« ignore mes instructions précédentes ») sont exclues
volontairement pour limiter les faux positifs.

Limite assumée : aucun détecteur par règles n'est exhaustif. Cette couche est
mesurée par scripts/redteam_report.py sur tests/redteam_corpus.py.
"""
import re
from dataclasses import dataclass, field

from app.detectors.normalize import OBFUSCATION_VIEWS, build_views

RISK_THRESHOLD = 50
BORDERLINE_MIN = 20  # score « suspect mais sous le seuil » : candidat au classifieur LLM
OBFUSCATION_BONUS = 25


def gap(lo: int, hi: int) -> str:
    """Entre `lo` et `hi` mots quelconques (paresseux)."""
    return rf"(?:\w+\W+){{{lo},{hi}}}?"


# ---------------------------------------------------------------------------
# Briques réutilisées
# ---------------------------------------------------------------------------
V_OVR_FR = (
    r"(?:ignor(?:e|ez|er)|oubli(?:e|ez|er)|neglig(?:e|ez|er)|annul(?:e|ez|er)|desobei\w*|contourn(?:e|ez|er)|"
    r"outrepass\w+|passe(?:z)? outre|fai(?:s|tes) abstraction|(?:tiens|tenez|tient) (?:plus |pas )?compte|"
    r"arrete(?:z)? de (?:suivre|respecter|obeir a)|cesse(?:z)? de (?:suivre|respecter|obeir a)|"
    r"(?:suis|suivez|respecte|respectez) (?:plus|pas))"
)
DET_FR = r"(?:(?:tout(?:es)?|tous|les|tes|vos|ces|ses|ta|votre|des|du|de|d|a|aux|au|l)\W+)"
V_OVR_EN = (
    r"(?:ignor(?:e|es|ing)|disregard(?:ing)?|forget(?:ting)?|overrid(?:e|es|ing)|bypass(?:es|ing)?|circumvent(?:ing)?|"
    r"discard(?:ing)?|neglect|nullify|disobey|cancel(?:ing|ling)?|void|scrap(?:ing|ping)?|drop(?:ing|ping)?|abandon(?:ing)?|skip(?:ing|ping)?|"
    r"stop\W+(?:following|obeying|respecting)|"
    r"(?:do\W+not|don\W?t|no\W+longer)\W+(?:follow|obey|respect))"
)
T_EN_ANY = (
    r"(?:instructions?|prompts?|guidelines?|directives?|directions?|programming|guardrails?|safeguards?|rules|rule|"
    r"restrictions?|constraints?|filters?|limitations?|polic(?:y|ies)|protocols?|training|configurations?|setup)"
)
V_ML = (
    r"(?:ignora|ignore|ignoriere|ignorier\w*|olvida\w*|esquec\w+|dimentica\w*|vergiss|missachte|umgehe|"
    r"ueberschreibe|uberschreibe|desconsider\w+|desobedece|trascura|aggira|omite)"
)
N_ML = (
    r"(?:instrucciones|indicaciones|directrices|instrucoes|diretrizes|istruzioni|direttive|anweisungen|"
    r"instruktionen|richtlinien|vorgaben|befehle|befehlen)"
)
V_REV_EN = (
    r"(?:reveal(?:ing)?|show|display|print|output|repeat|tell|give|leak|dump|expose|disclose|share|recite|"
    r"translate|summari[sz]e|paste|copy|provide|return|echo|spill|reproduce|quote|paraphrase|send)"
)
V_REV_FR = (
    r"(?:revele(?:z|r)?|affiche(?:z|r)?|montre(?:z|r)?|donne(?:z|r)?|dis|dites|dire|ecris|ecrivez|ecrire|"
    r"repete(?:z|r)?|recite(?:z|r)?|liste(?:z|r)?|imprime(?:z|r)?|copie(?:z|r)?|transmets|transmettre|"
    r"communique(?:z|r)?|traduis|traduisez|traduire|resume(?:z|r)?|fournis|fournissez|partage(?:z|r)?|"
    r"devoile(?:z|r)?|decris|decrire|expose(?:z|r)?|lis|lisez|cite(?:z|r)?|reproduis|exporte|envoie(?:z|r)?)"
)
ADJ_SECRET_EN = r"(?:system|hidden|secret|underlying|developer|confidential|core|internal system)"
ADJ_SECRET_FR = (
    r"(?:systemes?|initial(?:e|es|s)?|initiaux|internes?|caches?|cachees?|secrets?|secretes?|confidentiel\w*|"
    r"d origine|de depart|sous jacent\w*)"
)
NOT_DOC_EN = r"(?!\W+(?:for|template|examples?|design|ideas?|structure|format|works?|concept|meaning|basics|of\W+(?:a|an|my)\b))"
NOT_DOC_FR = r"(?!\W+(?:de|d|pour|du)\W+(?:mon|ma|mes|un|une|notre|nos|cet|ce|cette)\b)"
NOT_MY_FR = r"(?!(?:mes|mon|ma)\b)"
NOT_MY_EN = r"(?!my\b)"
SECRET_NOUN_EN = r"(?:api\W?keys?|passwords?|credentials|secrets?|tokens?|private\W+keys?|access\W+keys?|environment\W+variables|env\W+vars|\.env|connection\W+strings?)"
SECRET_NOUN_FR = r"(?:cles?\W+(?:d\W*)?api|cles?\W+privees?|mots?\W+de\W+passe|identifiants?|secrets?|jetons?|tokens?|variables?\W+d\W*environnement|credentials)"
NOT_TOPIC_EN = r"(?!\W+(?:format|requirements?|policy|policies|rules|manager|strength|reset|generator|best|examples?|tips?|length|complexity|hash\w*|storage|rotation|field|input|prefix|validation|regex)\b)"
DISABLE_TARGET_EN = (
    r"(?:safeguards?|guardrails?|filters?|restrictions?|content\W+(?:polic\w+|filters?)|censorship|moderation|"
    r"safety\W+(?:filters?|rules|guidelines|measures|features|checks|mechanisms|settings|protocols)|"
    r"ethical\W+(?:guidelines|constraints|restrictions)|limitations)"
)

# ---------------------------------------------------------------------------
# Règles : (libellé, poids, expression)
# ---------------------------------------------------------------------------
_RAW_RULES = [
    # ------------------------- annulation d'instructions -------------------------
    ("annulation d'instructions (fr)", 50,
     rf"\b{V_OVR_FR}\W+{NOT_MY_FR}(?:{DET_FR}){{0,3}}(?:(?:precedent\w*|anterieur\w*|initial\w*|systeme|de securite|de depart|ci dessus)\W+){{0,2}}"
     r"(?:instructions?|consignes?|directives?|programmation|garde ?fous?|prompts?|configuration|parametrage|parametres?)\b"),
    ("annulation de règles/restrictions (fr)", 50,
     rf"\b{V_OVR_FR}\W+{NOT_MY_FR}{gap(0, 2)}(?:tes|vos|ta|votre|toutes? les|precedentes?|anterieures?|initiales?|de securite|ethiques?)\W+"
     rf"{gap(0, 2)}(?:regles?|restrictions?|contraintes?|limites?|filtres?|protections?|securites?)\b"),
    ("« oublie tout ce qu'on t'a dit » (fr)", 50,
     r"\boubli(?:e|ez)\W+(?:tout|absolument tout)\W+ce\W+(?:qu|que)\W*(?:on|l\W*on|tu|vous|ils?)\W+(?:t\W*a|vous\W+a|as|avez|t\W*avait|a|avait)\W+"
     r"(?:dit|donne|demande|appris|ordonne|recu|instruit)\w*|\boubli(?:e|ez)\W+tout\W+ce\W+qui\W+(?:precede|est\W+(?:ecrit|au\W+dessus))"),
    ("annulation d'instructions (en)", 50,
     rf"\b{V_OVR_EN}\W+{NOT_MY_EN}{gap(0, 2)}(?:your|all|any|every|previous|prior|earlier|above|preceding|initial|original|system|safety|content|former|existing)\W+"
     rf"{gap(0, 2)}{T_EN_ANY}\b"),
    ("annulation du prompt/garde-fous (en)", 50,
     rf"\b{V_OVR_EN}\W+(?:the\W+|your\W+)?(?:system\W+(?:prompt|message|instructions?)|guardrails?|safeguards?|content\W+polic\w+)\b"),
    ("« forget everything » (en)", 50,
     r"\bforget\W+(?:everything|all|anything)\W+(?:you\W+(?:were|have|had|ve|know|learned|heard)|above|before|so\W+far|prior|earlier|that\W+(?:came|was)\W+before)"),
    ("« disregard whatever you were told » (en)", 50,
     r"\bdisregard\W+whatever\W+you\W+(?:were|ve\W+been|have\W+been)\W+told\b"),
    ("« obey me » sans autre qualificatif", 30, r"\band\W+(?:just\W+)?obey\W+me\b|\bet\W+obeis\W+(?:moi|uniquement\W+a\W+moi)\b"),
    ("annulation d'instructions (autres langues)", 50, rf"\b{V_ML}\W+{gap(0, 3)}{N_ML}\b"),
    ("annulation d'instructions (russe)", 50,
     r"игнориру\w*\s+.{0,30}(?:инструкц\w+|указан\w+|команд\w+)|забудь\s+.{0,20}(?:инструкц\w+|указан\w+)"),
    ("annulation d'instructions (chinois)", 50, r"忽略.{0,10}(?:之前|以上|上述).{0,10}(?:指令|指示|说明)|忘记.{0,10}(?:之前|以上).{0,10}(?:指令|指示)"),
    ("exfiltration du prompt système (russe)", 50, r"систем\w+\s+промпт|покажи\s+.{0,20}промпт|раскрой\s+.{0,20}(?:промпт|инструкц\w+)"),
    ("exfiltration du prompt système (chinois)", 50, r"系统提示|显示.{0,10}(?:提示词|指令)|泄露.{0,10}(?:提示词|指令)"),
    ("annulation d'instructions (néerlandais)", 50, r"\bnegeer\W+" + gap(0, 3) + r"instructies\b"),
    ("paraphrase d'annulation (« setup / configuration obsolète »)", 50,
     r"\byour\W+(?:earlier|previous|prior|old)\W+setup\W+(?:no\W+longer\W+applies|is\W+(?:void|invalid|obsolete|deprecated))\b|"
     r"\b(?:treat|consider)\W+(?:the\W+)?(?:rules|guidelines|instructions|setup|configuration)\W+you\W+(?:were\W+given|received|had)\W+as\W+"
     r"(?:void|invalid|no\W+longer\W+applicable|obsolete)\b|\bpolicy\W+is\W+deprecated\b|"
     r"\bskip\W+your\W+(?:guidelines|instructions|rules)\W+(?:this\W+once|just\W+this\W+time|for\W+now)\b"),
    ("paraphrase d'annulation (fr, configuration/mise à jour)", 50,
     r"\b(?:oublie|oubliez)\W+la\W+configuration\W+que\W+(?:t\W*a|vous\W+a)\W+(?:donnee?|fournie?|transmise?)\b|"
     r"\breinitialise\W?(?:\W+toi)?\b" + gap(0, 8) + r"\bignor\w+\W+ce\W+qui\W+(?:t\W*a|vous\W+a)\W+(?:ete\W+)?demande\b|"
     r"\bignor\w+\W+ce\W+qui\W+(?:t\W*a|vous\W+a)\W+(?:ete\W+)?demande\W+jusqu\W*ici\b|"
     r"\b(?:tu\W+dois|vous\W+devez)\W+(?:desormais|maintenant|dorenavant)\W+obeir\W+a\W+tout\W+ce\W+que\W+l\W*utilisateur\W+(?:demande|dit|ordonne)\b|"
     r"\btu\W+as\W+recu\W+une\W+mise\W+a\W+jour\W*:.{0,60}obeir\b"),
    ("« oublie tout » (autres langues)", 50,
     r"\bolvid\w+\W+todo\W+lo\W+que\W+(?:te|se|le)\W+(?:han|he|hemos|hicieron|dijeron|dije|dijo|dijimos)|"
     r"\besque(?:ca|ce|cer)\W+tudo\W+(?:o\W+)?que|\bvergiss\W+alles\W+(?:was|davor|vorher|bisher)|"
     r"\bdimentica\w*\W+tutto\W+(?:cio\W+che|quello\W+che)"),
    ("annulation de règles (autres langues)", 50,
     rf"\b{V_ML}\W+{gap(0, 3)}(?:tus|tuas|suas|tue|tuoi|deine|deinen|bisherigen|todas|tutte|alle)\W+{gap(0, 1)}"
     r"(?:reglas|regras|regole|regeln|restricciones|restricoes|restrizioni|einschrankungen|beschrankungen|limites|limiti)\b"),

    # ------------------------- exfiltration du prompt système -------------------------
    ("exfiltration du prompt système (en, « your/its »)", 55,
     rf"\b{V_REV_EN}\W+{gap(0, 5)}(?:your|ur|its)\W+{ADJ_SECRET_EN}\W+(?:prompts?|instructions?|messages?|configuration|rules|guidelines|directives|programming)\b"),
    ("exfiltration du prompt système (en, « the »)", 55,
     rf"\b{V_REV_EN}\W+{gap(0, 5)}the\W+{ADJ_SECRET_EN}\W+(?:prompts?|instructions?|messages?|configuration|rules|guidelines|directives|programming)\b{NOT_DOC_EN}"),
    ("exfiltration du prompt système (fr)", 55,
     rf"\b{V_REV_FR}\W+{gap(0, 5)}(?:ton|ta|tes|votre|vos|le|la|les|l|ce)\W+(?:prompts?|instructions?|consignes?|directives?|messages?)\W+{ADJ_SECRET_FR}\b{NOT_DOC_FR}"),
    ("exfiltration de la configuration interne (fr)", 55,
     rf"\b{V_REV_FR}\W+{gap(0, 4)}(?:ton|ta|tes|votre|vos)\W+(?:configuration|parametres|reglages|regles)\W+{ADJ_SECRET_FR}\b"),
    ("exfiltration : « dis-moi les consignes secrètes » (fr)", 55,
     rf"\b{V_REV_FR}\W+{gap(0, 4)}(?:tes|vos|les|ces)\W+(?:consignes?|instructions?|directives?)\W+{ADJ_SECRET_FR}\b"),
    ("question sur le prompt système (fr)", 55,
     r"\bquel(?:le)?s?\W+(?:est|sont|etait|etaient)\W+(?:ton|ta|tes|votre|vos)\W+(?:(?:prompt|instructions?|consignes?|directives?)\W+"
     rf"{ADJ_SECRET_FR}|prompt\W+systeme|instructions?\W+initiales?)"),
    ("question sur des instructions cachées reçues (fr)", 50,
     rf"\bquel(?:le)?s?\W+(?:instructions?|consignes?|directives?|prompts?)\W+{ADJ_SECRET_FR}\W+(?:as\W+tu|avez\W+vous)\W+(?:recu\w*|obtenu\w*|recues?)\b"),
    ("question sur le prompt système (en)", 55,
     r"\bwhat\W+(?:is|are|was|were)\W+your\W+(?:system|initial|original|hidden|secret|underlying|developer)\W+(?:prompt|instructions?|rules|guidelines|directives|message)"),
    ("demande de révéler ses instructions (en/fr, sans adjectif)", 40,
     rf"\b(?:(?:what|whats)\W+(?:is|are|were)\W+your\W+(?:prompt|instructions?|rules|guidelines)|{V_REV_EN}\W+{gap(0, 3)}your\W+(?:instructions?|prompt|guidelines|directives)|"
     rf"quel(?:le)?s?\W+(?:est|sont)\W+(?:ton|ta|tes|votre|vos)\W+(?:prompt|instructions?|consignes?)|{V_REV_FR}\W+{gap(0, 3)}(?:tes|ton|votre|vos)\W+(?:instructions?|consignes?|prompt|directives?))\b"),
    ("exfiltration : texte avant le premier message (en)", 50,
     r"\bwhat\W+text\W+(?:appears|is|comes)\W+before\W+(?:my|your|the)\W+first\W+message\b|"
     r"\bbegin\W+your\W+reply\W+with\W+the\W+exact\W+text\W+of\W+your\W+(?:setup|system|initial)\W+message\b|"
     r"\brepeat\W+the\W+text\W+that\W+appears\W+before\W+"),
    ("exfiltration : réciter le texte de configuration (fr)", 50,
     r"\b(?:reciter?|repeter?|recopier?)\W+le\W+texte\W+de\W+configuration\b|"
     r"\bque\W+t\W*a\W+t\W+on\W+dit\W+avant\W+(?:cette\W+conversation|notre\W+discussion|ce\W+message)\b"),
    ("« répète tout ce qui précède » (en)", 55,
     rf"\b(?:repeat|print|output|echo|recite|copy|say|write\W+out|reproduce|display|show)\W+{gap(0, 3)}(?:everything|all|the\W+words|the\W+text|the\W+message|the\W+content|text)\W+"
     r"(?!(?:i|you|we|they)\W+(?:said|wrote|mentioned|asked|told)\W+)" + gap(0, 2) +
     r"(?:above|before\W+this|preceding|prior\W+to\W+this)\b"),
    ("« répète tout ce qui précède » (fr)", 55,
     rf"\b(?:repete\w*|imprime\w*|recopie\w*|reproduis\w*|affiche\w*|ecris\w*|copie\w*)\W+{gap(0, 3)}(?:tout|le\W+texte|les\W+mots|le\W+contenu|le\W+message)\W+{gap(0, 2)}"
     r"(?:precede|precedent|ci\W+dessus|au\W+dessus|plus\W+haut|avant\W+ce)\b"),
    ("exfiltration du prompt système (es/de/it/pt)", 55,
     r"\b(?:revela|muestra|muestrame|imprime|repite|dime|dame|escribe|comparte|ensena|traduce|resume|enumera)\W+"
     rf"{gap(0, 4)}(?:prompt|instrucciones|indicaciones|configuracion|reglas)\W+(?:del\W+sistema|de\W+sistema|iniciales|internas|ocultas|secretas|originales)\b|"
     r"\b(?:zeige|zeig|verrate|gib|nenne|wiederhole|drucke|offenbare|teile|schreibe|nenn|sag|gebe)\W+"
     rf"{gap(0, 4)}(?:system\W?prompts?|system\W?anweisungen?|system\W?nachricht|anfangsanweisungen|urspruenglichen\W+anweisungen|versteckten\W+anweisungen|internen\W+anweisungen)\b|"
     r"\b(?:mostra|rivela|stampa|ripeti|dimmi|dammi|scrivi|traduci)\W+"
     rf"{gap(0, 4)}(?:prompt|istruzioni)\W+(?:di\W+sistema|iniziali|interne|nascoste|segrete)\b|"
     r"\b(?:revele|mostre|mostra|imprima|repita|diga|escreva|traduza)\W+"
     rf"{gap(0, 4)}(?:prompt|instrucoes)\W+(?:do\W+sistema|de\W+sistema|iniciais|internas|ocultas|secretas)\b"),

    # ------------------------- jailbreak par personnage / mode -------------------------
    ("réassignation de rôle sans restriction (fr)", 50,
     r"\b(?:tu\W+es|vous\W+etes|tu\W+deviens|deviens|tu\W+vas\W+devenir|tu\W+incarnes|imagine|suppose|fais\W+semblant|fais\W+comme\W+si|joue\W+le\W+role|agis\W+comme|comporte\W+toi\W+comme|simule|incarne)\W+"
     rf"{gap(0, 8)}(?:sans\W+(?:aucune?\W+|tout(?:es)?\W+)?(?:restriction|regle|limite|filtre|censure|contrainte|ethique|morale)s?|non\W+(?:filtre|censure)|debride|jailbreak\w*|"
     r"libre\W+de\W+toute?s?\W+(?:restriction|regle|limite|contrainte)s?)"),
    ("réassignation de rôle sans restriction (en)", 50,
     r"\b(?:you\W+are|you\W+re|youre|you\W+will\W+be|you\W+ll\W+be|become|act\W+as|acting\W+as|behave\W+(?:as|like)|pretend(?:\W+to\W+be|\W+you\W+are|\W+that\W+you\W+are)?|"
     r"role\W?play\W+as|play\W+the\W+role\W+of|simulate|imagine\W+(?:you\W+are|that\W+you\W+are)|from\W+now\W+on,?\W+you\W+(?:are|will|must|can|have))\W+"
     rf"{gap(0, 6)}(?:dan|unrestricted|unfiltered|uncensored|jailbroken|unlimited|evil|malicious|amoral|omnipotent|god\W+mode|not\W+bound\W+by|"
     r"without\W+(?:any\W+)?(?:rules|restrictions|limits|limitations|filters|guidelines|ethics|censorship)|"
     r"free\W+(?:from|of)\W+(?:all\W+)?(?:rules|restrictions|limits|filters))\b"),
    ("« do anything now » / DAN", 50,
     r"\bdo\W+anything\W+now\b|\bdan\W+mode\b|\bdan\W+(?:jailbreak|prompt)\b|\b(?:you\W+are|you\W+re|tu\W+es|act\W+as|acting\W+as|become|deviens|comme|called|appele|nomme|named)\W+dan\b"),
    ("persona sans règles (soft)", 35,
     r"\b(?:pretend|act|behave|imagine|fais\W+semblant|simule|suppose)\b\W+" + gap(0, 8) +
     r"(?:no\W+(?:rules|restrictions|limits|limitations|filters|guidelines|ethics|content\W+polic\w+|censorship)|"
     r"sans\W+(?:restriction|filtre|limite|censure)s?)"),
    ("persona « rogue/free » sans limites", 50,
     r"\b(?:act|behave)\W+(?:like|as)\W+(?:a\W+)?(?:rogue|renegade|free|liberated)\W+(?:ai|assistant|model|bot)\W+(?:\w+\W+){0,4}?(?:never\W+refus\w+|no\W+limits?|without\W+limits?|anything)\b|"
     r"\byour\W+safety\W+(?:layer|filter|system)\W+is\W+(?:now\W+)?off\b|\bconfirm\W+(?:it\W+)?by\W+answering\W+" + gap(0, 3) + r"without\W+censor"),
    ("persona sans limites (fr, filtre désactivé)", 50,
     r"\bton\W+filtre\W+de\W+securite\W+est\W+desactive\b|\bconfirme\W+(?:le\W+)?en\W+repondant\W+a\W+tout\b"),
    ("persona « réponds comme une IA sans limite » (fr)", 50,
     r"\b(?:reponds?|repondez|agis|comporte\W?toi|ecris)\W+comme\W+(?:le\W+ferait|si\W+tu\W+etais|si\W+vous\W+etiez)\W+(?:une\W+)?ia\W+"
     r"sans\W+(?:aucune?\W+)?(?:restriction|limite|regle|filtre|censure|contrainte)s?\W+(?:morale|ethique)?\b"),
    ("« réponds à tout / sans refuser »", 25,
     r"\b(?:answer|respond\W+to|reply\W+to)\W+(?:anything|everything)\b|\bnever\W+(?:refuse|say\W+no)\b|\bno\W+matter\W+what\b|"
     r"\brepond(?:s|ez)?\W+(?:a\W+)?(?:tout|n\W*importe\W+quoi)\b|\bsans\W+(?:jamais\W+)?refuser\b"),
    ("désactivation des garde-fous (en)", 50,
     rf"\b(?:disable|deactivate|turn\W+off|switch\W+off|remove|lift|bypass|circumvent|jailbreak|break)\W+{gap(0, 3)}(?:your|all|any)\W+{gap(0, 2)}{DISABLE_TARGET_EN}\b"),
    ("désactivation des garde-fous (fr)", 50,
     rf"\b(?:desactiv|desarm|suppr|enlev|retir|coup|leve|neutralis|contourn|desinhib)\w*\W+{gap(0, 3)}(?:tes|vos|tous\W+les|toutes\W+les|tout|les|ces)\W+{gap(0, 2)}"
     r"(?:garde\W?fous?|protections?|securites?|restrictions?|censure|limites?\W+ethiques?|mesures?\W+de\W+securite|filtres?\W+de\W+(?:securite|contenu|moderation)|moderation)\b|"
     r"\b(?:desactiv|desarm|suppr|enlev|retir|coup|neutralis|contourn|desinhib)\w*\W+(?:tes|vos)\W+filtres?\b"),
    ("activation d'un mode explicitement sans restriction", 50,
     r"\b(?:enter|activate|enable|switch\W+to|go\W+into|turn\W+on)\W+(?:the\W+)?(?:unrestricted|unfiltered|uncensored|unlimited|jailbreak(?:ed)?)\W+mode\b|"
     r"\b(?:active[rz]?|passe[rz]?\W+en|entre[rz]?\W+en)\W+mode\W+(?:sans\W+(?:filtre|restriction|limite)s?|libre|illimite)\b"),
    ("activation d'un mode de contournement (impératif)", 35,
     r"\b(?:active[rz]?|activate|enable|enter|switch\W+to|go\W+into|turn\W+on|passe[rz]?\W+en|mets?\W+toi\W+en|entre[rz]?\W+en|bascule[rz]?\W+en|lance[rz]?)\W+"
     rf"{gap(0, 2)}(?:mode\W+(?:developpeur|dev|dieu|god|sudo|admin|administrateur|debug|maintenance|root|sans\W+(?:filtre|restriction|limite)s?|libre|illimite)|"
     r"(?:developer|dev|god|dan|sudo|admin|debug|root|maintenance|unrestricted|jailbreak(?:ed)?)\W+mode|jailbreak)\b"),
    ("mot-clé de contournement connu", 35, r"\bjailbreak(?:ed|ing)?\b"),
    ("« plus aucune règle » (fr/en)", 50,
     r"\b(?:tu\W+n\W*as|vous\W+n\W*avez)\W+(?:plus|desormais)\W+(?:aucune?|de)\W+(?:regle|restriction|limite|filtre|contrainte)s?\b|"
     r"\b(?:you|u)\W+(?:have|hav)\W+no\W+(?:rules|restrictions|limits|limitations|filters|guidelines|ethics|boundaries)\b|"
     r"\bno\W+longer\W+(?:bound|restricted|limited|constrained|subject)\b"),
    ("demande de suppression des garde-fous", 30,
     r"\bsans\W+(?:aucune?\W+)?(?:restriction|filtre|censure|limite)s?\b|\bwithout\W+(?:any\W+)?(?:restrictions?|filters?|censorship|limits?)\b|"
     r"\b(?:no|zero)\W+(?:filters?|censorship)\b"),

    # ------------------------- usurpation de rôle / délimiteurs -------------------------
    ("délimiteur de conversation usurpé", 50,
     r"<\|\s*(?:im\W?start|im\W?end|endoftext|system|assistant|user)\s*\|>|\[/?inst\]|<<\s*/?\s*sys\s*>>|</?\s*(?:system|instructions?|assistant)\s*>|"
     r"(?:^|\n)\s*\[\s*system\s*\]"),
    ("commande d'autorité usurpée (« SYSTEM OVERRIDE »)", 50,
     r"\bsystem\W+override\b|\bpriority\W+level\W+0\W+command\b|\boverride\W+code\W+accepted\b"),
    ("en-tête de rôle « système » usurpé", 45,
     r"(?:^|\n|[.!?]\s)\s*#{0,4}\s*(?:system|developer|admin(?:istrator)?|root)\s*:|(?:^|\n)\s*#{2,}\s*(?:system|instructions?|new\W+instructions?|admin|developer)\b"),
    ("annonce de nouvelles instructions", 45,
     r"\b(?:nouvelles?|new|updated?|revised|additional|real|actual|true|vraies?)\W+(?:system\W+|systeme\W+)?(?:instructions?|consignes?|directives?|task|tache|prompt)\W*(?::|are\b|is\b|sont\b|est\b)"),
    ("marqueur de fin de prompt système", 45,
     r"-{3,}\W*(?:end|begin|start|fin|debut)\W+(?:of\W+)?(?:system|prompt|instructions?|user|conversation|context)"),
    ("annonce « message du système »", 40,
     r"\b(?:message|notice|avis|alerte|alert)\W+(?:du|from|de\W+la|from\W+the)\W+(?:systeme|system|admin\w*|developpeur|developer|securite|security)\W*:"),
    ("restrictions déclarées levées", 45,
     r"\b(?:les\W+)?(?:restrictions?|garde\W?fous?|filtres?|limites?)\W+(?:sont|ont\W+ete|est)\W+(?:levee?s?|desactivee?s?|supprimee?s?|retiree?s?|suspendue?s?)\b|"
     r"\b(?:restrictions?|safeguards?|guardrails?|filters?|limits?)\W+(?:have\W+been|are|has\W+been|is)\W+(?:lifted|removed|disabled|suspended|deactivated|turned\W+off)\b"),
    ("usurpation d'identité du créateur du modèle", 35,
     r"\b(?:je\W+suis|i\W+am|i\W+m|this\W+is|c\W+est)\W+(?:ton|votre|your|le|the)\W+(?:\w+\W+){0,2}?(?:developpeur|createur|concepteur|programmeur|developer|creator|maker|engineer|administrateur|administrator|admin)\W+"
     r"(?:\w+\W+){0,3}?(?:chez|at|of|from|de)\W+(?:openai|anthropic|google|meta|microsoft|the\W+company)\b|\b(?:i\W+am|je\W+suis)\W+(?:your|ton|votre)\W+(?:developer|creator|developpeur|createur)\b"),
    ("code d'autorisation invoqué", 35,
     r"\b(?:authori[sz]ation|auth|override|admin|master|access|security|maintenance)\W+(?:code|key|token|password|phrase)\W+\w+"),
    ("« vous êtes en mode maintenance/debug »", 45,
     r"\byou\W+are\W+now\W+in\W+(?:a\W+)?(?:maintenance|debug|test|admin|developer|unrestricted)\W+mode\b|\bvous\W+etes\W+(?:maintenant\W+)?en\W+mode\W+(?:maintenance|debug|test|admin)\b"),
    ("« reveal all data »", 40,
     r"\b(?:reveal|show|dump|print|output|send)\W+" + gap(0, 2) + r"(?:all|every|the\W+whole|entire|complete|full)\W+" + gap(0, 1) +
     r"(?:data|secrets?|users?|records|database|credentials|passwords|conversation|history)\b"),
    ("octroi d'accès complet", 40,
     r"\bgrant\W+(?:\w+\W+){0,2}?(?:full|admin|root|unrestricted|elevated)\W+(?:access|privileges|rights|permissions)\b|\b(?:accorde|donne)\W+(?:\w+\W+){0,2}?acces\W+(?:complet|total|admin)\b"),
    ("déclaration d'autorité de l'utilisateur", 35,
     r"\bthe\W+user\W+is\W+(?:an?\W+)?(?:admin\w*|authori[sz]ed|verified|developer|owner|root)\b|\bl\W*utilisateur\W+est\W+(?:un\W+)?(?:admin\w*|autorise|verifie|developpeur|proprietaire)\b"),

    # ------------------------- exfiltration de secrets / données -------------------------
    ("demande de secrets (en, générique fort)", 45,
     rf"\b(?:give|send)\W+me\W+(?:all|every)\W+{gap(0, 2)}{SECRET_NOUN_EN}\b{NOT_TOPIC_EN}"),
    ("demande de secrets (en, possessif)", 50,
     rf"\b(?:reveal|show|give|print|leak|send|dump|expose|tell|share|display|output|list|retrieve|fetch|read|extract|provide|disclose|echo)\W+{gap(0, 4)}"
     rf"(?:your|the\W+(?:stored|saved|internal|hidden|secret|server|system|admin))\W+{gap(0, 2)}{SECRET_NOUN_EN}\b{NOT_TOPIC_EN}"),
    ("demande de secrets accessibles au modèle (en)", 50,
     rf"\b{SECRET_NOUN_EN}\W+(?:(?:that|which)\W+)?(?:you\W+(?:have|possess|know|can\W+access|hold)|(?:of|on|from)\W+the\W+(?:server|system))\b|"
     rf"\b(?:reveal|show|give|print|list|dump)\W+{gap(0, 3)}{SECRET_NOUN_EN}\W+(?:you\W+(?:have|possess|know|can\W+access|hold)|(?:of|on|from)\W+the\W+(?:server|system))"),
    ("demande de secrets (fr, possessif)", 50,
     rf"\b(?:donne|donnez|revele|reveler|affiche|montre|dis|envoie|transmets|communique|liste|extrais|recupere|fournis|partage)\w*\W+{gap(0, 4)}"
     rf"(?:ta|ton|tes|votre|vos)\W+{gap(0, 2)}{SECRET_NOUN_FR}\b"),
    ("demande de secrets (fr, avec qualificatif d'accès)", 50,
     rf"\b(?:donne|donnez|revele|reveler|affiche|montre|dis|envoie|transmets|communique|liste|extrais|recupere|fournis|partage)\w*\W+{gap(0, 4)}"
     rf"(?:les|toutes\W+les|tous\W+les)\W+{gap(0, 2)}{SECRET_NOUN_FR}\W+(?:\w+\W+){{0,4}}?"
     r"(?:auxquell?e?s?\W+tu\W+as\W+acces|auxquell?e?s?\W+vous\W+avez\W+acces|que\W+tu\W+(?:connais|possedes|as|detiens)|que\W+vous\W+(?:connaissez|possedez|avez|detenez))\b|"
     rf"\bquel(?:le)?s?\W+(?:sont|est)\W+(?:les|le|la|ton|ta|tes|vos|votre)\W+{gap(0, 1)}{SECRET_NOUN_FR}\W+"
     r"(?:\w+\W+){0,3}?(?:stockes?|enregistres?|dans\W+(?:ta|ton|tes|votre|la|le)\W+(?:configuration|systeme|memoire|environnement|contexte)|"
     r"que\W+tu\W+(?:connais|possedes|as|detiens)|auxquell?e?s?\W+tu\W+as\W+acces)\b"),
    ("réponse avec un secret", 40,
     r"\b(?:reponds?|repond|answer|reply|respond|repondez)\W+" + gap(0, 2) + r"(?:avec|with)\W+(?:le|la|ton|ta|the|your)\W+(?:mot\W+de\W+passe|password|cle\W+api|api\W+key|secret|prompt|token)\b"),
    ("image/lien Markdown à paramètres (exfiltration)", 45,
     r"!\[[^\]]*\]\(\s*https?://[^)\s]*[?&][^)\s]*=[^)\s]*\)"),
    ("données placées dans une URL", 50,
     r"\b(?:conversation|historique|history|donnees|data|secrets?|contexte|context|prompt)\W+" + gap(0, 4) + r"(?:dans|in|to|vers|a|en)\W+(?:l\W*)?(?:url|lien|link|query|parametre)\b|"
     r"\b(?:include|add|ajoute|insere|met(?:s|tez)?)\W+" + gap(0, 10) + r"(?:link|url|lien|image)\W+" + gap(0, 8) + r"(?:conversation|history|historique|data|donnees)\b"),
    ("envoi de données vers une URL", 50,
     r"\b(?:send|post|forward|transmit|upload|exfiltrate|envoie|envoyez|transmets|poste|telecharge)\W+" + gap(0, 6) +
     r"(?:conversation|history|historique|messages?|emails?|data|donnees|files?|fichiers?|secrets?|context|contexte|prompt)\W+" + gap(0, 4) + r"(?:to|vers|a|at)\W+https?://"),
    ("envoi de données vers une adresse courriel", 45,
     r"\b(?:send|forward|transmit|envoie|envoyez|transmets|transfere)\W+" + gap(0, 6) +
     r"(?:conversation|history|historique|messages?|emails?|data|donnees|files?|fichiers?|secrets?|context|contexte|prompt)\W+" + gap(0, 4) + r"(?:to|vers|a|at)\W+[\w.+-]+@[\w-]+\.\w+"),
    ("« output the API key »", 45,
     rf"\b(?:output|print|reveal|show|give|send|tell|display|leak|dump|return|reply\W+with|respond\W+with)\W+(?:me\W+)?(?:the|your|all|any)\W+{gap(0, 1)}{SECRET_NOUN_EN}\b{NOT_TOPIC_EN}"),

    # ------------------------- injection indirecte (attaque cachée dans un contenu) -------------------------
    ("adresse à l'IA dans un contenu (note/attention)", 45,
     r"\b(?:note|message|notice|attention|important|instruction|instructions|memo)\W+(?:to|for|a|pour)\W+(?:the\W+|l\W*)?(?:ai|a\W?i|ia|llm|assistant|chatbot|language\W+model|model|modele|agent)\b|"
     r"\ba\W+l\W*attention\W+de\W+l\W*(?:ai|ia|assistant|llm|agent)\b"),
    ("« dear AI » / « bonjour assistant »", 40,
     r"\b(?:dear|cher|chere|hey|hello|bonjour)\W+(?:ai|ia|llm|assistant|chatbot)\b"),
    ("« si tu es une IA »", 35,
     r"\bif\W+you\W+are\W+(?:an?\W+)?(?:ai|llm|language\W+model|assistant|chatbot|bot|machine)\b|\bsi\W+tu\W+es\W+(?:une?\W+)?(?:ia|intelligence\W+artificielle|llm|assistant|bot|machine)\b"),
    ("dissimulation à l'utilisateur", 45,
     r"\b(?:do\W+not|don\W?t|never|without)\W+" + gap(0, 2) + r"(?:tell|inform|mention|notify|alert|reveal|say)\W+" + gap(0, 2) + r"(?:the\W+)?(?:user|human|person|anyone|operator)\b|"
     r"\bne\W+(?:dis|dites|mentionne\w*|informe\w*|previens|preveniez|revele\w*)\W+(?:pas|jamais|rien)\W+" + gap(0, 2) + r"(?:a\W+l\W*utilisateur|a\W+l\W*humain|a\W+la\W+personne|a\W+personne|a\W+l\W*operateur)|"
     r"\bne\W+(?:pas|jamais)\W+(?:dire|informer|mentionner|reveler|prevenir)\W+(?:a\W+l|l)\W*utilisateur\b|\bsans\W+(?:le\W+)?(?:dire|informer|prevenir)\W+(?:a\W+l|l)\W*utilisateur\b"),
    ("texte caché (HTML/CSS)", 25,
     r"display\s*:\s*none|visibility\s*:\s*hidden|font\W?size\s*:\s*0|opacity\s*:\s*0|color\s*:\s*(?:white|#fff)|aria\W?hidden|<!--"),
    ("action cachée insérée dans un contenu (« silently... »)", 45,
     r"\bsilently\W+(?:bcc|cc|forward|send|copy|include|add|append)\b|\bdiscretement\W+(?:copie|transfere|envoie|ajoute)\b"),
    ("usurpation « AI system: » suivie d'un ordre", 50,
     r"\b(?:ai\W+system|assistant\W+system)\s*:\s*(?:cancel|ignore|disregard|override)\b"),
]

RULES = [(label, weight, re.compile(pattern, re.MULTILINE)) for label, weight, pattern in _RAW_RULES]

_DESCRIPTIVE_GUARD_LABELS = {"annulation d'instructions (fr)", "annulation de règles/restrictions (fr)"}


def _looks_descriptive_fr(text: str, start: int) -> bool:
    """Vrai si le verbe à `start` semble décrire un sujet tiers (« la fonction
    ignore… », « le script contourne… ») plutôt qu'un ordre donné à l'assistant.
    L'impératif et l'indicatif présent du français se conjuguent identiquement à
    la 2e personne informelle (« ignore »), donc le distinguo n'est pas dans le
    verbe lui-même mais dans ce qui précède : une conjonction introduisant une
    proposition subordonnée + un sujet technique tiers."""
    window = text[max(0, start - 45) : start]
    return bool(re.search(
        r"\b(?:que|qui|lorsque|quand|car|puisque|si)\s+(?:la|le|l\W|une?|cette|ce|mon|ton|son|notre|votre|leur)\s+"
        r"(?:fonction|methode|classe|script|code|algorithme|programme|module|test|processus|requete|regle|filtre)\w*\s*$",
        window,
    ))


def _score(text: str, rules) -> tuple[int, list]:
    score = 0
    matched = []
    for label, weight, pattern in rules:
        m = pattern.search(text)
        if not m:
            continue
        if label in _DESCRIPTIVE_GUARD_LABELS and _looks_descriptive_fr(text, m.start()):
            continue
        score += weight
        matched.append(label)
    return score, matched


# Règles appliquées à la vue « texte espacé » (toutes les lettres collées : « ignoreallprevious... »)
_RAW_SQUASHED = [
    ("annulation d'instructions (texte espacé)", 50,
     r"(?:ignore|ignorez|disregard|forget|override|bypass|oublie|oubliez|contourne|neglige)(?:all|any|every|your|the|les|toutes|tes|vos|ces|tout)*"
     r"(?:previous|prior|earlier|above|precedentes?|anterieures?|initiales?|system|systeme|safety)*"
     r"(?:instructions?|consignes?|directives?|rules|regles|guidelines|guardrails|safeguards|restrictions|prompt|gardefous)"),
    ("exfiltration du prompt système (texte espacé)", 55,
     r"(?:reveal|show|print|display|output|repeat|leak|revele|affiche|montre|donne|dis|ecris|repete)(?:me|moi|us|the|your|le|la|ton|ta|tes|mon|ma|mes|all|tout)*"
     r"(?:system|initial|hidden|secret|systeme)(?:prompt|instructions?|consignes?|message)"),
    ("mode de contournement (texte espacé)", 50, r"developermode|godmode|danmode|donanythingnow|jailbreak"),
]
SQUASHED_RULES = [(label, weight, re.compile(pattern)) for label, weight, pattern in _RAW_SQUASHED]


@dataclass
class InjectionScanResult:
    score: int
    matched_rules: list
    is_blocked: bool
    via_base64: bool = False
    views_hit: list = field(default_factory=list)
    borderline: bool = False


def scan(text: str) -> InjectionScanResult:
    views = build_views(text)

    score, matched = _score(views["principale"], RULES)
    views_hit = ["principale"] if score else []
    via_base64 = False

    for name, view in views.items():
        if name == "principale":
            continue
        s, m = _score(view, SQUASHED_RULES if name == "espace" else RULES)
        if s == 0:
            continue
        if name in OBFUSCATION_VIEWS:
            s += OBFUSCATION_BONUS
            m = [f"{label} [dissimulé : {name}]" for label in m] + [f"obfuscation détectée ({name})"]
        else:  # « fautes » : la vue corrigée révèle la même attaque (aucun bonus)
            m = [f"{label} [fautes de frappe corrigées]" for label in m]
        if s > score:
            score, matched, views_hit = s, m, [name]
            via_base64 = name == "base64"
        elif s == score and name not in views_hit:
            views_hit.append(name)

    return InjectionScanResult(
        score=score,
        matched_rules=matched,
        is_blocked=score >= RISK_THRESHOLD,
        via_base64=via_base64,
        views_hit=views_hit,
        borderline=BORDERLINE_MIN <= score < RISK_THRESHOLD,
    )
