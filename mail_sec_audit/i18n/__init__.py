"""Message catalogs for human-readable text.

Language: ``--lang``, then ``LC_ALL``, ``LC_MESSAGES``, ``LANG``; Russian for
``ru*`` locales, English otherwise. JSON keys never depend on the language.
"""

from __future__ import annotations

import string
from collections.abc import Mapping
from typing import Any, Optional

from ..render.sanitize import clean
from . import en, ru

CATALOGS: dict[str, Mapping[str, str]] = {"en": en.MESSAGES, "ru": ru.MESSAGES}
LANGUAGES = tuple(sorted(CATALOGS))


def select_language(cli_lang: Optional[str], env: Mapping[str, str]) -> str:
    if cli_lang:
        return cli_lang
    for name in ("LC_ALL", "LC_MESSAGES", "LANG"):
        value = env.get(name, "")
        if value:
            return "ru" if value.lower().startswith("ru") else "en"
    return "en"


def placeholders(template: str) -> set[str]:
    return {name for _, name, _, _ in string.Formatter().parse(template) if name}


class MissingMessage(KeyError):
    pass


class Translator:
    def __init__(self, lang: str, *, strict: bool = False) -> None:
        if lang not in CATALOGS:
            raise ValueError(f"unsupported language: {lang}")
        self.lang = lang
        self.catalog = CATALOGS[lang]
        self.strict = strict

    def __call__(self, key: str, params: Optional[Mapping[str, Any]] = None) -> str:
        template = self.catalog.get(key)
        if template is None:
            if self.strict:
                raise MissingMessage(key)
            template = CATALOGS["en"].get(key, key)
        values = {name: _value(v) for name, v in (params or {}).items()}
        try:
            return template.format_map(values)
        except (KeyError, IndexError, ValueError):
            if self.strict:
                raise
            return f"{template} {values}"


def _value(value: Any) -> str:
    if isinstance(value, (list, tuple, set, frozenset)):
        return ", ".join(clean(str(v), 120) for v in value)
    return clean(str(value), 300)
