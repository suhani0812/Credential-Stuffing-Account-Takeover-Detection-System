import pandas as pd

def analyze_global_threats(df):
    if df.empty: return "No data available.", "N/A"
    counts = df['CountryCode'].value_counts()
    top_country = counts.idxmax()
    if counts[top_country] > 10:
        report = f"AI Analysis: Detects high-density traffic from {top_country}."
        if top_country!='IN':
            suggestion = "Action: Implement Geo-Fencing for this region."
        else:
            suggestion="Action: Adaptive Rate Limiting recommended instead of Geo-Fencing to avoid service disruption for local users since high-density traffic is from IN."
    else:
        report = "Global traffic levels are within normal parameters."
        suggestion = "No immediate blocking required."
    return report, suggestion

def analyze_user_risk(data):
    if data.empty:
        return "No suspicious lateral movement detected.", "Continue monitoring."
    
    sites_hit = data['SiteId'].nunique()
    if sites_hit > 2:
        report = "AI ALERT: Lateral Movement detected! Multiple sites accessed rapidly."
        suggestion = "Action: Freeze account and force password reset."
    else:
        report = "Standard user session pattern detected."
        suggestion = "Keep account active."
    return report, suggestion

def analyze_reputation(df):
    low_rep = df[df['RepScore'] < 30]
    if not low_rep.empty:
        report = f"AI Analysis: {len(low_rep)} connections identified from high-risk nodes."
        suggestion = "Action: Blacklist IPs with RepScore < 30 immediately."
    else:
        report = "All active connections show acceptable reputation scores."
        suggestion = "No proactive blocking required."
    return report, suggestion