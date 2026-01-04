from __future__ import annotations

from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path


def load_eml(path: str | Path) -> EmailMessage:
    p = Path(path)
    data = p.read_bytes()
    msg = BytesParser(policy=policy.default).parsebytes(data)
    return msg


def get_header(msg: EmailMessage, name: str) -> str:
    v = msg.get(name)
    return str(v) if v else ""


def extract_body_text(msg: EmailMessage, limit_chars: int = 50_000) -> str:
    # Prefer text/plain, fallback to stripped text/html
    parts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition", "")).lower()
            if "attachment" in disp:
                continue
            if ctype == "text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            if msg.get_content_type() == "text/plain":
                parts.append(msg.get_content())
        except Exception:
            pass

    text = "\n".join([p for p in parts if p]).strip()
    if not text:
        # crude html fallback
        html = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/html":
                    try:
                        html = part.get_content()
                        break
                    except Exception:
                        pass
        else:
            if msg.get_content_type() == "text/html":
                try:
                    html = msg.get_content()
                except Exception:
                    pass
        if html:
            # very light tag stripping (no heavy deps)
            import re

            text = re.sub(r"<[^>]+>", " ", html)
            text = re.sub(r"\s+", " ", text).strip()

    return text[:limit_chars]
