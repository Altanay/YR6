#!/usr/bin/env python3

from __future__ import annotations

import json
import shlex
from dataclasses import asdict
from typing import List, Tuple

from core import ExposureScanner


def parse_input_line(line: str) -> Tuple[List[str], int, bool, str]:
    parts = shlex.split(line)

    targets: List[str] = []
    workers = 10
    insecure = False
    output = "out.json"

    i = 0
    while i < len(parts):
        part = parts[i]

        if part == "-w":
            if i + 1 >= len(parts):
                raise ValueError("'-w' için sayı belirtmelisin. Örnek: -w 20")
            try:
                workers = int(parts[i + 1])
            except ValueError as exc:
                raise ValueError("'-w' değeri sayı olmalı.") from exc
            i += 2
            continue

        if part == "-k":
            insecure = True
            i += 1
            continue

        if part == "-o":
            if i + 1 >= len(parts):
                raise ValueError("'-o' için çıktı dosyası belirtmelisin. Örnek: -o sonuc.json")
            output = parts[i + 1]
            i += 2
            continue

        targets.append(part)
        i += 1

    if not targets:
        raise ValueError("En az bir hedef girmelisin.")

    if workers < 1:
        raise ValueError("Worker sayısı en az 1 olmalı.")

    return targets, workers, insecure, output


def run(line: str) -> int:
    try:
        targets, workers, insecure, output = parse_input_line(line)

        print("\n[INFO] Tarama başlıyor...")
        print(f"[INFO] Hedefler : {', '.join(targets)}")
        print(f"[INFO] Workers  : {workers}")
        print(f"[INFO] TLS      : {'kapalı (-k)' if insecure else 'açık'}")
        print(f"[INFO] Output   : {output}")

        scanner = ExposureScanner(
            targets=targets,
            workers=workers,
            verify_ssl=not insecure,
            show_results=True,
        )

        findings = scanner.run()

        result = {
            "summary": {
                "targets": len(scanner.targets),
                "hits": len(findings),
            },
            "findings": [asdict(f) for f in findings],
        }

        with open(output, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, ensure_ascii=False)

        print(f"\n[OK] Sonuçlar kaydedildi: {output}")
        return 0

    except Exception as exc:
        print(f"\n[ERROR] {exc}")
        return 1