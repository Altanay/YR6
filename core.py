#!/usr/bin/env python3

from __future__ import annotations

import concurrent.futures
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

from rules import (
    BACKUP_BASES,
    BACKUP_SUFFIXES,
    EXACT_RULES,
    MAX_BODY_READ,
    USER_AGENT,
)


@dataclass
class Finding:
    url: str
    type: str
    hit: bool
    evidence: List[str]
    preview: str
    remediation: str
    next_step: str


def normalize_target(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    parsed = urlparse(target)
    if not parsed.netloc:
        raise ValueError(f"invalid target: {target}")

    return f"{parsed.scheme}://{parsed.netloc}"


def redact(text: str) -> str:
    patterns = [
        re.compile(
            r"(?im)^(\s*(?:APP_KEY|DB_PASSWORD|MAIL_PASSWORD|SECRET_KEY|API_KEY|ACCESS_TOKEN|JWT_SECRET|AWS_SECRET_ACCESS_KEY|STRIPE_SECRET)\s*=\s*)(.+)$"
        ),
        re.compile(
            r'(?im)("?(?:password|token|secret|authorization|apikey|api_key|client_secret)"?\s*[:=]\s*"?)([^"\n]+)("?)'
        ),
        re.compile(r"(?i)\bBearer\s+[A-Za-z0-9\-\._~\+\/]+=*"),
        re.compile(r"(?i)\bghp_[A-Za-z0-9]{20,}\b"),
        re.compile(r"(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
        re.compile(r"(?i)\bAKIA[0-9A-Z]{16}\b"),
        re.compile(r"(?i)\bAIza[0-9A-Za-z\-_]{35}\b"),
        re.compile(r"(?i)\bsk_live_[A-Za-z0-9]{16,}\b"),
        re.compile(r"(?i)\bpk_live_[A-Za-z0-9]{16,}\b"),
    ]

    out = text
    for pattern in patterns:
        try:
            if pattern.groups >= 2:
                out = pattern.sub(
                    lambda m: f"{m.group(1)}[REDACTED]"
                    + (m.group(3) if m.lastindex and m.lastindex >= 3 else ""),
                    out,
                )
            else:
                out = pattern.sub("[REDACTED]", out)
        except Exception:
            out = pattern.sub("[REDACTED]", out)

    return out


def sha_preview(text: str, limit: int = 300) -> str:
    return redact(text[:limit])


def response_text(resp: requests.Response) -> str:
    chunks: List[str] = []
    total = 0

    try:
        for chunk in resp.iter_content(chunk_size=4096, decode_unicode=True):
            if chunk is None:
                continue
            total += len(chunk)
            if total > MAX_BODY_READ:
                break
            chunks.append(chunk)
    except Exception:
        pass

    return "".join(chunks)


def html_title(text: str) -> str:
    match = re.search(r"(?is)<title[^>]*>(.*?)</title>", text)
    return match.group(1).strip() if match else ""


class ExposureScanner:
    def __init__(
        self,
        targets: List[str],
        workers: int = 10,
        verify_ssl: bool = True,
        show_results: bool = True,
    ) -> None:
        self.targets = [normalize_target(t) for t in targets]
        self.workers = max(1, workers)
        self.verify_ssl = verify_ssl
        self.show_results = show_results

    def build_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({"User-Agent": USER_AGENT})
        return session

    def fetch(
        self,
        session: requests.Session,
        url: str,
        method: str = "GET",
    ) -> Optional[requests.Response]:
        try:
            if method.upper() == "HEAD":
                return session.head(
                    url,
                    allow_redirects=False,
                    timeout=8,
                    verify=self.verify_ssl,
                )

            return session.get(
                url,
                allow_redirects=False,
                timeout=8,
                verify=self.verify_ssl,
                stream=True,
            )
        except requests.RequestException:
            return None

    def print_finding(self, finding: Finding) -> None:
        print("\n" + "=" * 80)
        print(f"[FOUND] {finding.type}")
        print(f"URL       : {finding.url}")
        print(f"EVIDENCE  : {', '.join(finding.evidence) if finding.evidence else '-'}")
        print(f"PREVIEW   : {finding.preview if finding.preview else '-'}")
        print(f"FIX       : {finding.remediation if finding.remediation else '-'}")
        print(f"NEXT STEP : {finding.next_step if finding.next_step else '-'}")
        print("=" * 80)

    def print_target_summary(self, target: str, findings: List[Finding]) -> None:
        print("\n" + "#" * 80)
        print(f"[TARGET] {target}")
        if findings:
            print(f"[HITS]   {len(findings)}")
        else:
            print("[HITS]   0")
            print("[INFO]   Herhangi bir eşleşme bulunamadı.")
        print("#" * 80)

    def scan_captcha_protection(self, session: requests.Session, target: str) -> List[Finding]:
        findings: List[Finding] = []

        resp = self.fetch(session, target, "GET")
        if not resp:
            return findings

        body = response_text(resp)
        title = html_title(body)

        signals: List[str] = []

        body_patterns = {
            "captcha-keyword": r"(?i)\bcaptcha\b",
            "recaptcha-keyword": r"(?i)\brecaptcha\b",
            "hcaptcha-keyword": r"(?i)\bhcaptcha\b",
            "cloudflare-challenge": r"(?i)\bcf-chl\b|challenge-platform|turnstile",
            "bot-protection-keyword": r"(?i)bot protection|verify you are human|human verification",
            "attention-required": r"(?i)attention required",
            "just-a-moment": r"(?i)just a moment",
            "why-do-i-have-to-complete-a-captcha": r"(?i)why do i have to complete a captcha",
            "g-recaptcha": r"(?i)g-recaptcha",
            "cf-turnstile": r"(?i)cf-turnstile",
        }

        title_patterns = {
            "title:attention-required": r"(?i)attention required",
            "title:just-a-moment": r"(?i)just a moment",
        }

        header_patterns = {
            "server:cloudflare": r"(?i)cloudflare",
            "cf-ray-header": r".+",
        }

        for name, pattern in body_patterns.items():
            if re.search(pattern, body):
                signals.append(name)

        for name, pattern in title_patterns.items():
            if re.search(pattern, title):
                signals.append(name)

        for header_name, pattern in header_patterns.items():
            if header_name == "cf-ray-header":
                value = resp.headers.get("CF-RAY", "")
            elif header_name == "server:cloudflare":
                value = resp.headers.get("Server", "")
            else:
                value = ""

            if value and re.search(pattern, value):
                signals.append(header_name)

        # Cloudflare vb. bazı sayfalarda 403/429/503 ile gelir
        if resp.status_code in (403, 429, 503) and signals:
            signals.append(f"status:{resp.status_code}")
        elif len(signals) >= 2:
            signals.append(f"status:{resp.status_code}")

        if len(set(signals)) >= 2:
            finding = Finding(
                url=target,
                type="captcha_or_bot_protection_detected",
                hit=True,
                evidence=list(dict.fromkeys(signals))[:10],
                preview=sha_preview(body),
                remediation="Tarama yapılan hedefte captcha veya anti bot tespit edildi.",
                next_step="Gerçek sonuç alamaya bilirisn. Anti bot sistemini aşmanın bir yolunu bul, özel session/cookie tanımla.",
            )
            findings.append(finding)

            if self.show_results:
                self.print_finding(finding)

        return findings

    def scan_exact_rules(self, session: requests.Session, target: str) -> List[Finding]:
        findings: List[Finding] = []

        for rule in EXACT_RULES:
            for path in rule["paths"]:
                url = urljoin(target, path)
                resp = self.fetch(session, url, rule.get("method", "GET"))
                if not resp:
                    continue

                if resp.status_code not in rule.get("status", [200]):
                    continue

                body = "" if rule.get("method", "GET").upper() == "HEAD" else response_text(resp)
                title = html_title(body)
                ctype = resp.headers.get("Content-Type", "")

                matched: List[str] = []

                for pattern in rule.get("body", []):
                    if re.search(pattern, body):
                        matched.append(pattern)

                for pattern in rule.get("title", []):
                    if re.search(pattern, title):
                        matched.append(f"title:{pattern}")

                for need in rule.get("ctype", []):
                    if need.lower() in ctype.lower():
                        matched.append(f"ctype:{need}")

                real_hits = [x for x in matched if not x.startswith("ctype:")]
                if len(real_hits) < rule.get("min", 1):
                    continue

                finding = Finding(
                    url=url,
                    type=rule["id"],
                    hit=True,
                    evidence=matched[:10],
                    preview=sha_preview(body),
                    remediation=rule.get("remediation", ""),
                    next_step=rule.get("next_step", ""),
                )

                findings.append(finding)

                if self.show_results:
                    self.print_finding(finding)

        return findings

    def scan_backup_files(self, session: requests.Session, target: str) -> List[Finding]:
        findings: List[Finding] = []

        for base in BACKUP_BASES:
            for suffix in BACKUP_SUFFIXES:
                path = f"{base}{suffix}"
                url = urljoin(target, path)
                resp = self.fetch(session, url)

                if not resp or resp.status_code != 200:
                    continue

                body = response_text(resp)
                ctype = resp.headers.get("Content-Type", "")

                signs: List[str] = []

                if re.search(
                    r"(?mi)^(APP_ENV|APP_KEY|DB_PASSWORD|MAIL_PASSWORD|DB_HOST|JWT_SECRET|AWS_SECRET_ACCESS_KEY)=",
                    body,
                ):
                    signs.append("env-like-content")

                if re.search(r"(?m)^\[core\]", body):
                    signs.append("git-config-like")

                if re.search(r"(?i)phpinfo\(\)|PHP Version", body):
                    signs.append("phpinfo-like")

                if re.search(r"(?i)sql dump|Dump completed|CREATE TABLE|INSERT INTO", body):
                    signs.append("sql-like")

                if re.search(r"(?i)password|token|authorization|secret|connectionString", body):
                    signs.append("secret-like-content")

                if "text" in ctype.lower() or "json" in ctype.lower() or signs:
                    finding = Finding(
                        url=url,
                        type="backup_exposure",
                        hit=True,
                        evidence=signs or [f"status:200", f"ctype:{ctype or 'unknown'}"],
                        preview=sha_preview(body),
                        remediation="Yedek dosyaları public alandan kaldır ve dizin listelemeyi kapat.",
                        next_step="Yedek içinde credential, müşteri verisi veya token varsa rotate ve olay incelemesi başlat.",
                    )

                    findings.append(finding)

                    if self.show_results:
                        self.print_finding(finding)

        return findings

    def scan_target(self, target: str) -> List[Finding]:
        session = self.build_session()
        findings: List[Finding] = []

        findings.extend(self.scan_captcha_protection(session, target))
        findings.extend(self.scan_exact_rules(session, target))
        findings.extend(self.scan_backup_files(session, target))

        dedup: Dict[Tuple[str, str], Finding] = {}
        for finding in findings:
            dedup[(finding.type, finding.url)] = finding

        final_findings = list(dedup.values())

        if self.show_results:
            self.print_target_summary(target, final_findings)

        return final_findings

    def run(self) -> List[Finding]:
        all_findings: List[Finding] = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as executor:
            futures = [executor.submit(self.scan_target, target) for target in self.targets]

            for future in concurrent.futures.as_completed(futures):
                try:
                    all_findings.extend(future.result())
                except Exception:
                    continue

        all_findings.sort(key=lambda x: (x.type, x.url))

        print("\n" + "*" * 80)
        print("[SCAN FINISHED]")
        print(f"[TARGET COUNT] {len(self.targets)}")
        print(f"[TOTAL HITS ]  {len(all_findings)}")
        print("*" * 80)

        return all_findings