from __future__ import annotations

import json
import socket
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import date, datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID


def _strip_scheme_host(s: str) -> str:
    """
    Accepts input like:
      - example.com
      - https://example.com/foo
      - example.com:8443
    Returns the host-ish portion only.
    """

    s = (s or "").strip()
    if not s:
        return ""
    if "://" in s:
        try:
            u = urllib.parse.urlparse(s)
            return (u.netloc or "").strip()
        except Exception:
            pass
    # Fallback: trim path/query fragments if user pasted a URL without scheme.
    for sep in ["/", "?", "#"]:
        if sep in s:
            s = s.split(sep, 1)[0].strip()
    return s


def normalize_domain_name(raw: str) -> str:
    s = _strip_scheme_host(raw)
    s = s.strip().lower().strip(".")
    if not s:
        return ""
    # Drop optional port for domain objects.
    if ":" in s and s.rsplit(":", 1)[-1].isdigit():
        s = s.rsplit(":", 1)[0]
    return s[:253]


def parse_host_port(raw: str, *, default_port: int = 443) -> tuple[str, int]:
    s = _strip_scheme_host(raw)
    s = (s or "").strip().strip(".")
    if not s:
        return ("", int(default_port))
    host = s
    port = int(default_port)

    # IPv6 in brackets: [::1]:443
    if host.startswith("[") and "]" in host:
        left, rest = host.split("]", 1)
        host = left.lstrip("[").strip()
        rest = rest.strip()
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
        return (host, port)

    # host:port (avoid splitting IPv6 without brackets; we keep it simple)
    if ":" in host and host.rsplit(":", 1)[-1].isdigit():
        host, p = host.rsplit(":", 1)
        port = int(p)
    return (host.strip(), port)


def _iso_to_date(s: str) -> date | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        # RDAP uses ISO 8601, often with Z.
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(s)
        return dt.date()
    except Exception:
        return None


def lookup_domain_rdap(domain: str, *, timeout: float = 8.0) -> dict:
    """
    Best-effort domain lookup via RDAP.
    Uses rdap.org as a convenient bootstrap proxy.
    """

    name = normalize_domain_name(domain)
    if not name or "." not in name:
        return {}

    url = f"https://rdap.org/domain/{urllib.parse.quote(name)}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = resp.read()
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return {}

    out: dict[str, object] = {}

    # Expiry date
    expires = None
    try:
        events = data.get("events") or []
        if isinstance(events, list):
            for ev in events:
                if not isinstance(ev, dict):
                    continue
                act = (ev.get("eventAction") or "").lower().strip()
                if act not in {"expiration", "expiry"}:
                    continue
                expires = _iso_to_date(str(ev.get("eventDate") or ""))
                if expires:
                    break
    except Exception:
        expires = None
    if expires:
        out["expires_on"] = expires

    # Registrar (best-effort)
    registrar = None
    try:
        if isinstance(data.get("registrarName"), str):
            registrar = (data.get("registrarName") or "").strip()
        if not registrar:
            entities = data.get("entities") or []
            if isinstance(entities, list):
                for ent in entities:
                    if not isinstance(ent, dict):
                        continue
                    roles = ent.get("roles") or []
                    if not (isinstance(roles, list) and any(str(r).lower() == "registrar" for r in roles)):
                        continue
                    v = ent.get("vcardArray")
                    if not (isinstance(v, list) and len(v) == 2 and isinstance(v[1], list)):
                        continue
                    for row in v[1]:
                        # ["fn", {}, "text", "Registrar Name"]
                        if isinstance(row, list) and len(row) >= 4 and str(row[0]).lower() == "fn":
                            registrar = str(row[3] or "").strip()
                            break
                    if registrar:
                        break
    except Exception:
        registrar = None
    if registrar:
        out["registrar"] = registrar[:200]

    return out


@dataclass(frozen=True)
class CertLookup:
    issuer: str = ""
    serial_number: str = ""
    fingerprint_sha256: str = ""
    not_before: date | None = None
    not_after: date | None = None
    san_dns: list[str] | None = None
    subject_cn: str = ""


def lookup_tls_certificate(common_name: str, *, timeout: float = 6.0, verify: bool = False) -> CertLookup | None:
    host, port = parse_host_port(common_name)
    if not host:
        return None

    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                der = ssock.getpeercert(binary_form=True)
    except Exception:
        # Fallback: try a public CT index (crt.sh) when direct TLS is unreachable.
        return lookup_tls_certificate_crtsh(host, timeout=max(4.0, float(timeout)))

    try:
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None

    issuer = ""
    try:
        issuer = cert.issuer.rfc4514_string()
    except Exception:
        issuer = ""

    serial = ""
    try:
        serial = hex(int(cert.serial_number))[2:].upper()
    except Exception:
        serial = ""

    fp = ""
    try:
        fp = cert.fingerprint(hashes.SHA256()).hex()
    except Exception:
        fp = ""

    nb = None
    na = None
    try:
        # cryptography >= 41
        nb = cert.not_valid_before_utc.date()  # type: ignore[attr-defined]
        na = cert.not_valid_after_utc.date()  # type: ignore[attr-defined]
    except Exception:
        try:
            nb = cert.not_valid_before.replace(tzinfo=timezone.utc).date()
            na = cert.not_valid_after.replace(tzinfo=timezone.utc).date()
        except Exception:
            nb = None
            na = None

    san_dns: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = ext.value
        for x in sans:
            if isinstance(x, x509.DNSName):
                n = (str(x.value) or "").strip().lower().strip(".")
                if n and n not in san_dns:
                    san_dns.append(n)
    except Exception:
        san_dns = []

    subject_cn = ""
    try:
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if cns:
            subject_cn = str(cns[0].value or "").strip()
    except Exception:
        subject_cn = ""

    return CertLookup(
        issuer=issuer[:255],
        serial_number=serial[:128],
        fingerprint_sha256=fp[:128],
        not_before=nb,
        not_after=na,
        san_dns=san_dns[:200],
        subject_cn=subject_cn[:253],
    )


def _parse_crtsh_dt(s: str) -> date | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        # Common format: "2026-01-01T00:00:00"
        if s.endswith("Z"):
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        else:
            dt = datetime.fromisoformat(s)
        return dt.date()
    except Exception:
        try:
            # Common format: "2026-01-01 00:00:00"
            dt = datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
            return dt.date()
        except Exception:
            return None


def lookup_tls_certificate_crtsh(host_or_cn: str, *, timeout: float = 8.0) -> CertLookup | None:
    """
    Best-effort certificate metadata lookup via crt.sh JSON.
    This is a fallback when direct TLS to the host is unavailable.

    Notes:
      - Doesn't provide serial/fingerprint reliably.
      - Can return stale results; we attempt to pick the "best" row.
    """

    host = normalize_domain_name(host_or_cn)
    if not host or "." not in host:
        return None

    url = f"https://crt.sh/?q={urllib.parse.quote(host)}&output=json"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            raw = resp.read()
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None

    if not isinstance(data, list) or not data:
        return None

    # Choose the newest cert that hasn't expired yet; otherwise the newest overall.
    today = datetime.now(timezone.utc).date()
    best = None
    best_key = None
    for row in data[:200]:
        if not isinstance(row, dict):
            continue
        na = _parse_crtsh_dt(str(row.get("not_after") or ""))
        nb = _parse_crtsh_dt(str(row.get("not_before") or ""))
        issuer = str(row.get("issuer_name") or "").strip()
        cn = str(row.get("common_name") or "").strip()
        # name_value typically contains SANs separated by \n
        name_value = str(row.get("name_value") or "").strip()
        sans = []
        if name_value:
            for part in name_value.replace("\r", "\n").split("\n"):
                p = normalize_domain_name(part)
                if p and "." in p and p not in sans:
                    sans.append(p)
        if na is None and nb is None and not issuer and not name_value and not cn:
            continue
        alive = bool(na and na >= today)
        key = (
            1 if alive else 0,
            na or date.min,
            nb or date.min,
        )
        if best_key is None or key > best_key:
            best_key = key
            best = (issuer, cn, nb, na, sans)

    if not best:
        return None
    issuer, cn, nb, na, sans = best
    return CertLookup(
        issuer=issuer[:255],
        serial_number="",
        fingerprint_sha256="",
        not_before=nb,
        not_after=na,
        san_dns=sans[:200],
        subject_cn=(cn or host)[:253],
    )


def apply_domain_public_info(*, obj, info: dict, force: bool = False) -> bool:
    changed = False
    if not info:
        return False

    expires = info.get("expires_on")
    if isinstance(expires, date) and (force or obj.expires_on is None):
        if obj.expires_on != expires:
            obj.expires_on = expires
            changed = True

    registrar = info.get("registrar")
    if isinstance(registrar, str) and registrar.strip() and (force or not (obj.registrar or "").strip()):
        registrar2 = registrar.strip()[:200]
        if (obj.registrar or "") != registrar2:
            obj.registrar = registrar2
            changed = True

    return changed


def apply_ssl_public_info(*, obj, info: CertLookup, force: bool = False) -> bool:
    changed = False
    if not info:
        return False

    for field, val in [
        ("issuer", info.issuer),
        ("serial_number", info.serial_number),
        ("fingerprint_sha256", info.fingerprint_sha256),
    ]:
        if val and (force or not (getattr(obj, field) or "").strip()):
            if getattr(obj, field) != val:
                setattr(obj, field, val)
                changed = True

    if info.not_before and (force or obj.not_before is None):
        if obj.not_before != info.not_before:
            obj.not_before = info.not_before
            changed = True

    if info.not_after and (force or obj.not_after is None):
        if obj.not_after != info.not_after:
            obj.not_after = info.not_after
            changed = True

    if info.san_dns is not None:
        san_text = ", ".join(info.san_dns)
        if san_text and (force or not (obj.subject_alt_names or "").strip()):
            if (obj.subject_alt_names or "") != san_text:
                obj.subject_alt_names = san_text
                changed = True

    return changed


def dns_names_for_cert(*, common_name: str, info: CertLookup) -> list[str]:
    names: list[str] = []
    cn = normalize_domain_name(common_name)
    if cn and "." in cn:
        names.append(cn)
    for n in info.san_dns or []:
        n2 = normalize_domain_name(n)
        if n2 and "." in n2 and n2 not in names:
            names.append(n2)
    # Strip wildcard noise for Domain creation/linking.
    out: list[str] = []
    for n in names:
        n2 = n[2:] if n.startswith("*.") else n
        if n2 and n2 not in out:
            out.append(n2)
    return out[:200]
