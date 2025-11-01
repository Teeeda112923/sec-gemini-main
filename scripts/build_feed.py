import os, json, requests, datetime as dt

os.makedirs("output", exist_ok=True)
OUT = "output/latest.json"

def fetch_nvd(days=7, api_key=None):
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    pub_start = (dt.datetime.utcnow() - dt.timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000")
    params = {
        "pubStartDate": pub_start + " UTC+00:00",
        "resultsPerPage": "2000"
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    r = requests.get(base, params=params, headers=headers, timeout=60)
    r.raise_for_status()
    return r.json()

def to_items(nvd_json):
    out = []
    for v in nvd_json.get("vulnerabilities", []):
        cve = v.get("cve", {})
        cve_id = cve.get("id") or ""
        if not cve_id:
            continue
        descs = cve.get("descriptions", [])
        summary = descs[0]["value"] if descs else ""
        metrics = cve.get("metrics", {})
        cvss = None
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics and metrics[key]:
                cvss = metrics[key][0]["cvssData"]["baseScore"]
                break
        refs = []
        for r in cve.get("references", []):
            refs.append(["reference", r.get("url")])
        out.append({
            "cve": cve_id,
            "summary": summary,
            "description": summary,
            "cvss": cvss,
            "published": cve.get("published"),
            "exploit_confirmed": False,
            "cisa_kev": False,
            "references": refs,
        })
    return out

def main():
    api_key = os.getenv("NVD_API_KEY")
    data = fetch_nvd(days=30, api_key=api_key)
    items = to_items(data)
    # フィルタ: CVSS9.0以上または実悪用（ここではNVDのみなのでCVSS9.0以上）
    filtered = []
    for it in items:
        try:
            if float(it.get("cvss", 0.0)) >= 9.0:
                filtered.append(it)
        except Exception:
            pass
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(filtered, f, ensure_ascii=False, indent=2)
    print(f"wrote {OUT} ({len(filtered)} items)")

if __name__ == "__main__":
    main()
