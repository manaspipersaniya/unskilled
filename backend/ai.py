"""Claude-powered summaries and Q&A over an APK's analysis results."""
import json

import anthropic

MODEL = "claude-opus-5-5"
SYSTEM = (
    "You assist digital-forensics investigators reviewing Android APK analysis results. "
    "Explain findings in plain language for a law-enforcement report. Base every statement on the JSON "
    "evidence provided and cite the field it came from; say so when the evidence is insufficient. "
    "Note that benign apps can legitimately use sensitive APIs, so weigh context before calling something malicious."
)


def _context(r):
    """Compact view of the analysis so the prompt stays small."""
    s = r["static"]
    return {
        "file": s["file_name"], "package": s["package"], "app_name": s["app_name"],
        "sdk": [s["min_sdk"], s["target_sdk"]], "hashes": s["hashes"],
        "permissions": [p["short"] for p in s["permissions"] if p["level"] in ("dangerous", "suspicious")],
        "manifest_flags": s["manifest_flags"], "certificate_flags": s["certificate"]["flags"],
        "exported_components": s["exported_count"],
        "code_api_categories": r["code"]["api_by_category"],
        "secrets": r["code"]["secrets"][:15],
        "evasion": [f"{f['severity']}: {f['title']} - {f['evidence'][:160]}" for f in r["evasion"]["findings"]],
        "iocs": {k: v[:20] if isinstance(v, list) else v for k, v in r["iocs"].items()},
        "risk": {"score": r["risk"]["score"], "level": r["risk"]["level"],
                 "top_reasons": [c["reason"] for c in r["risk"]["contributions"][:12]]},
    }


def _call(prompt):
    client = anthropic.Anthropic()
    response = client.beta.messages.create(
        model=MODEL,
        max_tokens=16000,
        system=SYSTEM,
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        output_config={"effort": "medium"},
        messages=[{"role": "user", "content": prompt}],
    )
    if response.stop_reason == "refusal":
        return None
    return "".join(b.text for b in response.content if b.type == "text").strip()


def _fallback_summary(r):
    s, risk = r["static"], r["risk"]
    lines = [f"{s['app_name'] or s['package']} ({s['package']}) scored {risk['score']}/100 ({risk['level']})."]
    lines += [f"- {c['reason']}" for c in risk["contributions"][:8]]
    return "\n".join(lines)


def summarize(r):
    prompt = ("Write a concise forensic summary (max ~250 words) of this APK: what it appears to be, the strongest "
              "indicators, notable evasion techniques, and recommended next investigative steps.\n\n"
              + json.dumps(_context(r), ensure_ascii=False))
    try:
        text = _call(prompt)
    except (anthropic.AuthenticationError, anthropic.PermissionDeniedError, TypeError):
        return _fallback_summary(r) + "\n\n(AI summary unavailable: no valid Anthropic credentials.)"
    except anthropic.RateLimitError:
        return _fallback_summary(r) + "\n\n(AI summary unavailable: rate limited, try again shortly.)"
    except (anthropic.APIStatusError, anthropic.APIConnectionError) as e:
        return _fallback_summary(r) + f"\n\n(AI summary unavailable: {type(e).__name__}.)"
    return text or _fallback_summary(r)


def ask(r, question):
    prompt = (f"Analysis results:\n{json.dumps(_context(r), ensure_ascii=False)}\n\n"
              f"Investigator question: {question}")
    try:
        text = _call(prompt)
    except (anthropic.AuthenticationError, anthropic.PermissionDeniedError, TypeError):
        return {"answer": "AI unavailable: set ANTHROPIC_API_KEY or run `ant auth login`."}
    except anthropic.RateLimitError:
        return {"answer": "AI unavailable: rate limited, try again shortly."}
    except (anthropic.APIStatusError, anthropic.APIConnectionError) as e:
        return {"answer": f"AI unavailable: {type(e).__name__}."}
    return {"answer": text or "The model declined to answer this question."}
