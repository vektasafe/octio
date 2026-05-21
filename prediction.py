import json
import requests
import os
import pathlib
from datetime import datetime, timezone
from dotenv import load_dotenv

BASE = pathlib.Path("/home/james-warren/Projects/Vektasafe Projects/octio")
load_dotenv(BASE / ".env")

API_KEY = os.getenv("OPENROUTER_API_KEY").strip('"')
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "google/gemma-3-27b-it"

def load_data():
    with open(BASE / "reputation.json") as f:
        reputation = json.load(f)
    with open(BASE / "profiles.json") as f:
        profiles = json.load(f)
    return reputation, profiles

def build_context(reputation, profiles):
    rep_summary = []
    for domain, record in reputation.items():
        rep_summary.append({
            "domain": domain,
            "times_flagged": record["times_flagged"],
            "score": record["score"],
            "label": record["label"],
            "highest_severity": record["highest_severity"],
            "vt_malicious": record["total_vt_malicious"],
            "first_seen": record["first_seen"][:10],
            "last_seen": record["last_seen"][:10]
        })

    prof_summary = []
    for protocol, record in profiles.items():
        prof_summary.append({
            "protocol": protocol,
            "risk_rating": record["risk_rating"],
            "total_threats": record["total_threats"],
            "confirmed_threats": record["confirmed_threats"],
            "high_risk": record["high_risk"],
            "max_reputation_score": record["max_reputation_score"],
            "domains_flagged": len(record["domains"])
        })

    return rep_summary, prof_summary

def predict_with_gemma(rep_summary, prof_summary):
    prompt = f"""You are a predictive threat intelligence analyst for OCTIO, a Web3 security system.

Below is the CURRENT DOMAIN REPUTATION DATA showing how many times each domain has been flagged and its cumulative threat score:
{json.dumps(rep_summary, indent=2)}

Below is the CURRENT PROTOCOL RISK PROFILE DATA showing which platforms are being actively impersonated:
{json.dumps(prof_summary, indent=2)}

Based on this data, predict:
1. Which attack campaigns are currently escalating and likely to peak in the next 24-72 hours
2. Which DeFi protocols or Web3 platforms are most likely to be targeted next
3. What the dominant attack vector will be
4. What early warning signals are already visible in the data

Respond in JSON only, no other text:
{{
    "threat_level": "ELEVATED" or "HIGH" or "CRITICAL",
    "escalating_campaigns": [
        {{
            "campaign": "description of the campaign",
            "evidence": "what in the data supports this",
            "peak_window": "24h or 48h or 72h",
            "confidence": "HIGH" or "MEDIUM" or "LOW"
        }}
    ],
    "predicted_next_targets": [
        {{
            "target": "protocol or platform name",
            "reasoning": "why this target is likely next",
            "risk": "HIGH" or "CRITICAL"
        }}
    ],
    "dominant_attack_vector": "description of primary attack method",
    "early_warning_signals": ["list of observable signals already present in the data"],
    "recommended_actions": [
        "specific action DeFi protocols should take in the next 24 hours"
    ],
    "analyst_advisory": "3-4 sentence forward-looking threat advisory for DeFi protocol teams"
}}"""

    for attempt in range(3):
        try:
            response = requests.post(
                OPENROUTER_URL,
                headers={
                    "Authorization": f"Bearer {API_KEY}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": MODEL,
                    "messages": [{"role": "user", "content": prompt}]
                },
                timeout=60
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"].strip()
            if content.startswith("```"):
                content = content.split("```")[1]
                if content.startswith("json"):
                    content = content[4:]
            return json.loads(content.strip())
        except Exception as e:
            print("  Attempt " + str(attempt+1) + " failed: " + str(e))
    return None

def run_prediction():
    print("\n=== OCTIO Predictive Threat Intelligence ===")
    print("Timestamp: " + datetime.now(timezone.utc).isoformat())
    print("Loading reputation and profile data...")

    reputation, profiles = load_data()
    rep_summary, prof_summary = build_context(reputation, profiles)

    print("Domains tracked: " + str(len(rep_summary)))
    print("Protocols profiled: " + str(len(prof_summary)))
    print("Running Gemma 4 predictive analysis...\n")

    prediction = predict_with_gemma(rep_summary, prof_summary)
    if not prediction:
        print("Prediction failed.")
        return

    print("THREAT LEVEL: " + prediction["threat_level"])
    print()

    print("ESCALATING CAMPAIGNS:")
    for c in prediction["escalating_campaigns"]:
        print("  Campaign: " + c["campaign"])
        print("  Evidence: " + c["evidence"])
        print("  Peak window: " + c["peak_window"] + " | Confidence: " + c["confidence"])
        print()

    print("PREDICTED NEXT TARGETS:")
    for t in prediction["predicted_next_targets"]:
        print("  " + t["target"] + " -- " + t["risk"] + " risk")
        print("  " + t["reasoning"])
        print()

    print("DOMINANT ATTACK VECTOR:")
    print("  " + prediction["dominant_attack_vector"])
    print()

    print("EARLY WARNING SIGNALS:")
    for s in prediction["early_warning_signals"]:
        print("  " + s)
    print()

    print("RECOMMENDED ACTIONS (next 24 hours):")
    for a in prediction["recommended_actions"]:
        print("  " + a)
    print()

    print("ANALYST ADVISORY:")
    print("  " + prediction["analyst_advisory"])

    output = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "domains_analysed": len(rep_summary),
        "protocols_analysed": len(prof_summary),
        "prediction": prediction
    }

    with open(BASE / "prediction.json", "w") as f:
        json.dump(output, f, indent=2)

    print("\nPrediction saved to prediction.json")
    return output

if __name__ == "__main__":
    run_prediction()
