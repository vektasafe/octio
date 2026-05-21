import json
import pathlib
from datetime import datetime, timezone
from collections import defaultdict

BASE = pathlib.Path("/home/james-warren/Projects/Vektasafe Projects/octio")

SEVERITY_SCORE = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

def normalise_target(target):
    target = target.lower()
    if any(x in target for x in ["metamask", "meta mask"]):
        return "MetaMask"
    if any(x in target for x in ["uniswap"]):
        return "Uniswap"
    if any(x in target for x in ["ledger"]):
        return "Ledger"
    if any(x in target for x in ["coinbase"]):
        return "Coinbase"
    if any(x in target for x in ["binance"]):
        return "Binance"
    if any(x in target for x in ["gmail", "google"]):
        return "Google/Gmail"
    if any(x in target for x in ["apple", "icloud"]):
        return "Apple/iCloud"
    if any(x in target for x in ["netflix", "netfliix"]):
        return "Netflix"
    if any(x in target for x in ["roblox", "robiox"]):
        return "Roblox"
    if any(x in target for x in ["zoom", "meet", "livemeet"]):
        return "Video Conferencing"
    if any(x in target for x in ["babylon"]):
        return "Babylon Chain"
    if any(x in target for x in ["aave"]):
        return "Aave"
    if any(x in target for x in ["compound"]):
        return "Compound"
    if any(x in target for x in ["opensea"]):
        return "OpenSea"
    if any(x in target for x in ["trust wallet", "trustwallet"]):
        return "Trust Wallet"
    if any(x in target for x in ["bet365"]):
        return "bet365"
    if any(x in target for x in ["dpd"]):
        return "DPD"
    if any(x in target for x in ["ref finance", "ref"]):
        return "Ref Finance"
    return target.title()[:30]

def build_profiles():
    indicators_path = BASE / "indicators.json"
    reputation_path = BASE / "reputation.json"

    if not indicators_path.exists():
        print("No indicators.json found. Run monitor.py first.")
        return

    with open(indicators_path) as f:
        indicators = json.load(f)

    reputation = {}
    if reputation_path.exists():
        with open(reputation_path) as f:
            reputation = json.load(f)

    profiles = defaultdict(lambda: {
        "protocol": "",
        "total_threats": 0,
        "confirmed_threats": 0,
        "high_risk": 0,
        "severity_counts": {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0},
        "threat_types": set(),
        "domains": [],
        "first_seen": None,
        "last_seen": None,
        "max_reputation_score": 0,
        "risk_rating": ""
    })

    for indicator in indicators:
        if not indicator.get("gemma_analysis", {}).get("is_threat"):
            continue

        analysis = indicator["gemma_analysis"]
        target_raw = analysis.get("target", "Unknown")
        protocol = normalise_target(target_raw)
        severity = analysis.get("severity", "LOW")
        url = indicator["url"]
        domain = url.split("/")[2] if len(url.split("/")) > 2 else url
        timestamp = indicator.get("timestamp", "")

        rep = reputation.get(domain, {})
        label = rep.get("label", "")
        rep_score = rep.get("score", 0)

        p = profiles[protocol]
        p["protocol"] = protocol
        p["total_threats"] += 1
        p["severity_counts"][severity] = p["severity_counts"].get(severity, 0) + 1
        p["threat_types"].add(analysis.get("threat_type", "UNKNOWN"))

        if label == "CONFIRMED_THREAT":
            p["confirmed_threats"] += 1
        elif label == "HIGH_RISK":
            p["high_risk"] += 1

        if domain not in p["domains"]:
            p["domains"].append(domain)

        if rep_score > p["max_reputation_score"]:
            p["max_reputation_score"] = rep_score

        if not p["first_seen"] or timestamp < p["first_seen"]:
            p["first_seen"] = timestamp
        if not p["last_seen"] or timestamp > p["last_seen"]:
            p["last_seen"] = timestamp

    for protocol, p in profiles.items():
        p["threat_types"] = list(p["threat_types"])
        score = (p["confirmed_threats"] * 30) + (p["high_risk"] * 15) + (p["total_threats"] * 5)
        if score >= 60:
            p["risk_rating"] = "CRITICAL"
        elif score >= 30:
            p["risk_rating"] = "HIGH"
        elif score >= 15:
            p["risk_rating"] = "MEDIUM"
        else:
            p["risk_rating"] = "LOW"

    print("\n=== OCTIO Protocol Risk Profiles ===")
    print(f"Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"Protocols under active threat: {len(profiles)}\n")
    print("-" * 80)

    sorted_profiles = sorted(profiles.values(), key=lambda x: x["max_reputation_score"], reverse=True)

    for p in sorted_profiles:
        print(f"Protocol:         {p['protocol']}")
        print(f"Risk Rating:      {p['risk_rating']}")
        print(f"Total Threats:    {p['total_threats']}")
        print(f"Confirmed:        {p['confirmed_threats']} | High Risk: {p['high_risk']}")
        print(f"Severity:         HIGH={p['severity_counts'].get('HIGH',0)} MEDIUM={p['severity_counts'].get('MEDIUM',0)} CRITICAL={p['severity_counts'].get('CRITICAL',0)}")
        print(f"Max Rep Score:    {p['max_reputation_score']}")
        print(f"Domains flagged:  {len(p['domains'])}")
        print(f"Threat types:     {p['threat_types']}")
        if p['first_seen']:
            print(f"First seen:       {p['first_seen'][:10]}")
        print()

    profiles_output = {k: v for k, v in profiles.items()}
    with open(BASE / "profiles.json", "w") as f:
        json.dump(profiles_output, f, indent=2, default=str)

    print("-" * 80)
    critical = sum(1 for p in profiles.values() if p["risk_rating"] == "CRITICAL")
    high = sum(1 for p in profiles.values() if p["risk_rating"] == "HIGH")
    print(f"CRITICAL risk protocols: {critical}")
    print(f"HIGH risk protocols:     {high}")
    print(f"Profiles saved to profiles.json")

    return profiles

if __name__ == "__main__":
    build_profiles()
