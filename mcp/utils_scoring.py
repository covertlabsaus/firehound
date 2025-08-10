from __future__ import annotations

from rapidfuzz import fuzz


def score_app(term: str, title: str, developer: str | None = None, dev_hint: str | None = None) -> float:
    t = term.strip().lower()
    ttl = title.strip().lower() if title else ""
    score = fuzz.token_set_ratio(t, ttl) / 100.0
    if dev_hint and developer:
        score += 0.1 * (fuzz.token_set_ratio(dev_hint.lower(), developer.lower()) / 100.0)
    return max(0.0, min(1.0, score))


