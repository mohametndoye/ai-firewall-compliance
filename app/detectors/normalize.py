"""Normalisation anti-obfuscation.

Neutralise les techniques courantes utilisées pour contourner une détection par
règles/mots-clés, avant même d'appliquer les règles de détection PII ou
d'injection. Toutes ces techniques sont documentées dans la littérature sur les
attaques adverses contre les filtres de texte :

1. Caractères invisibles / de contrôle bidirectionnel insérés au milieu de mots.
2. Homoglyphes (cyrillique/grec qui ressemblent à du latin) et formes Unicode
   compatibles (pleine largeur, lettres cerclées, gras mathématique...).
3. Casse / accents / ponctuation irréguliers.
4. Texte « espacé » (i g n o r e, i.g.n.o.r.e) et « leet » (1gn0r3).
5. Contenu encodé : base64, hexadécimal, ROT13, texte inversé.
6. Fautes de frappe volontaires (instuctions, promt) : rapprochées de mots-clés
   sensibles par distance d'édition bornée.

`build_views(text)` retourne plusieurs « vues » du même texte ; les détecteurs
appliquent leurs règles à chacune. Ces vues sont internes : le texte transmis
au LLM n'est jamais altéré par cette normalisation.

Limite assumée : on neutralise les techniques *connues*. Un attaquant inventif
peut toujours en imaginer une nouvelle — d'où la défense en profondeur (limite de
débit, classifieur LLM, journalisation) plutôt qu'un filtre unique.
"""
import base64
import binascii
import codecs
import re
import unicodedata
from functools import lru_cache

# --------------------------------------------------------------------------
# Étape de base
# --------------------------------------------------------------------------
INVISIBLE_CHARS = re.compile(r"[​-‏‪-‮⁠-⁤⁦-⁩﻿­᠎͏]")
ZERO_WIDTH_CHARS = INVISIBLE_CHARS  # alias conservé pour compatibilité

_HOMOGLYPHS = {
    # cyrillique minuscule / majuscule
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w", "к": "k", "м": "m", "т": "t", "в": "b", "н": "h", "п": "n",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "У": "Y", "І": "I", "Ј": "J", "Ѕ": "S",
    # grec
    "ο": "o", "α": "a", "ρ": "p", "υ": "y", "ι": "i", "ν": "v", "ε": "e", "κ": "k", "τ": "t", "χ": "x",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P",
    "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
    # divers
    "ɡ": "g", "ո": "n", "ᴀ": "a", "ᴇ": "e", "ᴏ": "o", "ı": "i",
}
HOMOGLYPH_MAP = str.maketrans(_HOMOGLYPHS)

BASE64_CANDIDATE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}")
HEX_CANDIDATE = re.compile(r"(?<![0-9a-fA-F])(?:[0-9a-fA-F]{2}){10,}(?![0-9a-fA-F])")

_LATIN_RE = re.compile(r"[A-Za-z]")
_LOOKALIKE_RE = re.compile("[" + re.escape("".join(_HOMOGLYPHS)) + "]")
_WORD_TOKEN = re.compile(r"\w+", re.UNICODE)


def _fix_mixed_script_word(word: str) -> str:
    """Ne traduit les homoglyphes que si le mot mélange déjà du latin avec des
    caractères sosies (le cas d'une attaque : « Ignоrе » avec un о cyrillique
    au milieu de lettres latines). Un mot entièrement en cyrillique/grec — un
    texte légitime dans une autre langue — n'est pas touché, sinon on détruirait
    la langue au lieu de neutraliser une ruse."""
    if _LATIN_RE.search(word) and _LOOKALIKE_RE.search(word):
        return word.translate(HOMOGLYPH_MAP)
    return word


def normalize(text: str) -> str:
    """Version normalisée « légère » (utilisée aussi par la détection PII) :
    Unicode compatible, invisibles supprimés, homoglyphes ramenés au latin
    UNIQUEMENT dans les mots à script mixte, espaces horizontaux collapsés.
    Conserve casse, accents et retours à la ligne."""
    text = unicodedata.normalize("NFKC", text)
    text = INVISIBLE_CHARS.sub("", text)
    text = _WORD_TOKEN.sub(lambda m: _fix_mixed_script_word(m.group()), text)
    text = re.sub(r"[ \t]+", " ", text)
    return text


def strip_accents(text: str) -> str:
    decomposed = unicodedata.normalize("NFD", text)
    return unicodedata.normalize("NFC", "".join(c for c in decomposed if unicodedata.category(c) != "Mn"))


def canonical(text: str) -> str:
    """Forme canonique pour les règles de détection : minuscules, sans accents,
    apostrophes/tirets internes uniformisés, espaces collapsés (retours à la ligne conservés)."""
    text = normalize(text).casefold()
    text = strip_accents(text)
    text = text.replace("’", "'").replace("`", "'").replace("´", "'")
    text = re.sub(r"(?<=\w)[-_](?=\w)", " ", text)  # garde-fous -> garde fous ; im_start -> im start
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text.strip()


# --------------------------------------------------------------------------
# Vues secondaires
# --------------------------------------------------------------------------
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "€": "e", "!": "i"})
_LEETISH = re.compile(r"[a-z][01345 7@$][a-z]|[a-z][01345 7@$]\b|\b[01345 7@$][a-z]".replace(" ", ""))
SPACED_OUT = re.compile(r"(?<![a-z0-9])(?:[a-z0-9][ .\-_*·|/]){4,}[a-z0-9](?![a-z0-9])")


def leet_view(canon: str) -> str | None:
    """« 1gn0r3 4ll » -> « ignore all ». None si le texte n'a pas l'air « leet »."""
    if not _LEETISH.search(canon):
        return None
    return canon.translate(_LEET)


def squashed_view(canon: str) -> str | None:
    """Supprime tout séparateur quand le texte contient des lettres espacées
    (« i g n o r e », « i.g.n.o.r.e »). None sinon (évite de compresser du texte normal)."""
    if not SPACED_OUT.search(canon):
        return None
    return re.sub(r"[^a-z0-9]", "", canon)


def rot13_view(canon: str) -> str:
    return codecs.encode(canon, "rot13")


def reversed_view(canon: str) -> str:
    return canon[::-1]


def _looks_like_text(s: str) -> bool:
    if len(s) < 8:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\t")
    letters = sum(1 for c in s if c.isalpha() or c.isspace())
    return printable / len(s) >= 0.95 and letters / len(s) >= 0.7


def extract_base64_payloads(text: str) -> list[str]:
    """Décode les segments qui ressemblent à du base64 (standard ou URL-safe) et
    dont le contenu décodé est du texte lisible. Ré-essaie jusqu'à 2 fois si le
    résultat décodé ressemble lui-même à du base64 (encodage imbriqué) : on
    vérifie d'abord si c'est un candidat base64 valide avant de le considérer
    comme le texte final, sinon un double encodage s'arrêterait après le
    premier tour (le base64 intermédiaire, tout en lettres, ressemble déjà à
    du texte lisible)."""
    payloads = []
    for match in BASE64_CANDIDATE.finditer(text):
        candidate = match.group()
        for _ in range(3):
            padded_src = candidate.rstrip("=").replace("-", "+").replace("_", "/")
            padded = padded_src + "=" * (-len(padded_src) % 4)
            try:
                decoded = base64.b64decode(padded, validate=False).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                break
            stripped = decoded.strip()
            if BASE64_CANDIDATE.fullmatch(stripped) and not _looks_like_text(stripped):
                candidate = stripped
                continue
            if BASE64_CANDIDATE.fullmatch(stripped):
                try:
                    inner_padded_src = stripped.rstrip("=").replace("-", "+").replace("_", "/")
                    inner_padded = inner_padded_src + "=" * (-len(inner_padded_src) % 4)
                    inner_decoded = base64.b64decode(inner_padded, validate=False).decode("utf-8")
                    if _looks_like_text(inner_decoded) and not BASE64_CANDIDATE.fullmatch(inner_decoded.strip()):
                        payloads.append(inner_decoded)
                        break
                except (binascii.Error, UnicodeDecodeError, ValueError):
                    pass
            if _looks_like_text(decoded):
                payloads.append(decoded)
            break
    return payloads


def extract_hex_payloads(text: str) -> list[str]:
    payloads = []
    for match in HEX_CANDIDATE.finditer(text):
        try:
            decoded = bytes.fromhex(match.group()).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue
        if _looks_like_text(decoded):
            payloads.append(decoded)
    return payloads


# --------------------------------------------------------------------------
# Tolérance aux fautes de frappe : rapprochement de mots-clés sensibles
# --------------------------------------------------------------------------
FUZZY_KEYWORDS = sorted(
    {
        "ignore", "ignorez", "instructions", "instruction", "previous", "precedentes", "precedente", "precedent",
        "system", "systeme", "prompt", "prompts", "reveal", "revele", "revelez", "disregard", "override",
        "bypass", "forget", "restrictions", "restriction", "guidelines", "directives", "consignes", "jailbreak",
        "developer", "developpeur", "unrestricted", "unfiltered", "uncensored", "password", "credentials",
        "hidden", "secret", "confidential", "oublie", "oubliez", "contourne", "guardrails", "safeguards",
        "initial", "initiales", "anterieures", "disable", "desactive", "instrucciones", "anweisungen",
    }
)
_KW_BY_LEN: dict[int, list[str]] = {}
for _kw in FUZZY_KEYWORDS:
    _KW_BY_LEN.setdefault(len(_kw), []).append(_kw)
_KW_SET = set(FUZZY_KEYWORDS)
_WORD = re.compile(r"[a-z]{5,16}")


def _edit_distance(a: str, b: str, limit: int) -> int:
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        row_min = i
        for j, cb in enumerate(b, 1):
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            cur.append(v)
            row_min = min(row_min, v)
        if row_min > limit:
            return limit + 1
        prev = cur
    return prev[-1]


@lru_cache(maxsize=4096)
def _closest_keyword(word: str) -> str | None:
    if word in _KW_SET:
        return None
    for length in range(len(word) - 2, len(word) + 3):
        for kw in _KW_BY_LEN.get(length, ()):
            same_ends = word[0] == kw[0] and word[-1] == kw[-1]
            limit = 2 if (len(word) >= 6 and same_ends) else 1
            if word[0] != kw[0] and word[-1] != kw[-1] and limit == 1 and len(word) < 6:
                continue
            if _edit_distance(word, kw, limit) <= limit:
                return kw
    return None


def fuzzy_view(canon: str) -> str | None:
    """Remplace les mots proches d'un mot-clé sensible (fautes de frappe) par ce mot-clé.
    Retourne None si aucun mot n'a été remplacé."""
    changed = False

    def repl(m: re.Match) -> str:
        nonlocal changed
        kw = _closest_keyword(m.group())
        if kw:
            changed = True
            return kw
        return m.group()

    out = _WORD.sub(repl, canon)
    return out if changed else None


# --------------------------------------------------------------------------
# API principale
# --------------------------------------------------------------------------
OBFUSCATION_VIEWS = {"leet", "espace", "rot13", "inverse", "hex", "base64"}


def build_views(text: str) -> dict[str, str]:
    """Retourne {nom_de_vue: texte}. La vue "principale" est toujours présente."""
    canon = canonical(text)
    views: dict[str, str] = {"principale": canon}

    if (v := fuzzy_view(canon)) is not None:
        views["fautes"] = v
    if (v := leet_view(canon)) is not None:
        views["leet"] = v
    if (v := squashed_view(canon)) is not None:
        views["espace"] = v
    views["rot13"] = rot13_view(canon)
    views["inverse"] = reversed_view(canon)

    for payload in extract_base64_payloads(normalize(text)):
        views.setdefault("base64", canonical(payload))
    for payload in extract_hex_payloads(normalize(text)):
        views.setdefault("hex", canonical(payload))
    return views
