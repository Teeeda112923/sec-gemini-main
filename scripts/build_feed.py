#!/usr/bin/env python3
# scripts/build_feed.py
from __future__ import annotations

import os
import json
import time
from typing import Any, Dict, List, Tuple, Optional
from datetime import datetime, timedelta, timezone

import requests
from dateutil import parser as dtparser

# =========================================
# 設定
# =========================================
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()
LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", "30"))
RESULTS_PER_PAGE = 2000  # NVDの上限に合わせる
OUT_PATH = os.path.join("output", "latest.json")

# =========================================
# ユーティリティ
# =========================================
def _now_utc() -> datetime:
    return datetime.now(timezone.utc)

def _iso_utc(dt: datetime) -> str:
    # 秒精度 & 'Z'
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")

def _normalize_to_utc_str(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    try:
        # "YYYY-MM-DD" のような日付のみ→UTC 00:00Zで扱う
        st = s.strip()
        if len(st) == 10 and st[4] == "-" and st[7] == "-":
            st = st + "T00:00:00Z"
        dt = dtparser.isoparse(st)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        return _iso_utc(dt)
    except Exception:
        return None

def _to_float(x: Any) -> Optional[float]:
    try:
        return float(x)
    except Exception:
        return None

# =========================================
# NVD 2.0 API
# =========================================
def _nvd_headers() -> Dict[str, str]:
    h = {"User-Agent": "sec-gemini-feed-builder/1.0"}
    if NVD_API_KEY:
        # ドキュメント上は 'apiKey' ヘッダ（大文字小文字は無視される）
        h["apiKey"] = NVD_API_KEY
    return h

def _nvd_time_window(days: int) -> Tuple[str, str]:
    now = _now_utc()
    start = now - timedelta(days=days)
    return _iso_utc(start), _iso_utc(now)

def _extract_cvss(cve: Dict) -> Optional[float]:
    """
    NVD 2.0 metrics から CVSS 基本値を抽出（v4 -> v3.1 -> v3.0 の優先順）
    """
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV40", "cvssMetricV4"):
        arr = metrics.get(key)
        if isinstance(arr, list) and arr:
            data = (arr[0].get("cvssData") or {})
            sc = _to_float(data.get("baseScore"))
            if sc is not None:
                return sc
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if isinstance(arr, list) and arr:
            data = (arr[0].get("cvssData") or {})
            sc = _to_float(data.get("baseScore"))
            if sc is not None:
                return sc
    return None

def _extract_refs(cve: Dict) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    for ref in (cve.get("references") or []):
        url = ref.get("url") or ""
        if not url:
            continue
        title = ref.get("name") or ref.get("source") or "reference"
        out.append({"title": str(title), "url": str(url)})
    return out

def _extract_vendor_product(cve: Dict) -> Tuple[str, str]:
    """
    CPE からざっくり vendor/product を1件だけ抽出（存在すれば）
    """
    configs = cve.get("configurations") or {}
    nodes = configs.get("nodes") or []
    for node in nodes:
        matches = node.get("cpeMatch") or []
        for m in matches:
            cpe = m.get("criteria") or m.get("cpe23Uri") or ""
            parts = cpe.split(":")
            # cpe:2.3:a:vendor:product:version:...
            if len(parts) >= 5:
                vendor = parts[3].replace("_", " ")
                product = parts[4].replace("_", " ")
                return vendor, product
    return "", ""

def fetch_nvd(days: int, max_per_page: int = RESULTS_PER_PAGE, retry: int = 3, backoff: float = 1.5) -> List[Dict]:
    """
    直近 days 日の NVD 2.0 CVE をすべて取得し、フィード用に整形して返す。
    """
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start_iso, end_iso = _nvd_time_window(days)

    items: List[Dict] = []
    start_index = 0
    total_results = None

    while True:
        params = {
            "pubStartDate": start_iso,   # 必須
            "pubEndDate": end_iso,       # 必須
            "resultsPerPage": str(max_per_page),
            "startIndex": str(start_index),
        }

        attempt = 0
        while True:
            attempt += 1
            try:
                resp = requests.get(base, headers=_nvd_headers(), params=params, timeout=60)
                if resp.status_code == 429:
                    # レート制限：指数バックオフ
                    time.sleep(backoff ** attempt)
                    continue
                resp.raise_for_status()
                data = resp.json()
                break
            except Exception as e:
                if attempt >= retry:
                    raise
                time.sleep(backoff ** attempt)

        vulns = data.get("vulnerabilities") or []
        if total_results is None:
            total_results = data.get("totalResults") or 0

        for v in vulns:
            c = v.get("cve") or {}
            cve_id = (c.get("id") or "").strip()
            if not cve_id:
                continue

            # 概要（EN/JA優先）
            descs = c.get("descriptions") or []
            summary = ""
            for d in descs:
                lang = (d.get("lang") or "").lower()
                if lang in ("en", "ja"):
                    summary = d.get("value") or ""
                    break
            if not summary and descs:
                summary = descs[0].get("value") or ""

            published = _normalize_to_utc_str(c.get("published") or c.get("publishedDate"))

            vendor, product = _extract_vendor_product(c)
            cvss = _extract_cvss(c)
            refs = _extract_refs(c)

            items.append({
                "cve": cve_id,
                "title": summary[:120] if summary else cve_id,
                "summary": summary,
                "vendor": vendor,
                "product": product,
                "published": published,
                "cvss": cvss,
                "exploited": False,               # NVD単体では判別不可（後段でCISA等と突合）
                "references": refs,                # [{"title","url"}, ...]
            })

        # 次ページ判定
        start_index += len(vulns)
        if not vulns or start_index >= (total_results or 0):
            break

    return items

# =========================================
# メイン
# =========================================
def main():
    items = fetch_nvd(days=LOOKBACK_DAYS)

    out = {
        "generatedAt": _iso_utc(_now_utc()),
        "items": items,
    }

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    with open(OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    print(f"[ok] wrote {OUT_PATH} with {len(items)} items")

if __name__ == "__main__":
    main()
