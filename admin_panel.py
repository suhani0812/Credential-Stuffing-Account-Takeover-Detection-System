from flask import Flask, render_template, request, redirect, session, flash, send_file
from sqlalchemy import create_engine, text
import pandas as pd
from datetime import datetime, timedelta
import io

# Import your custom logic modules
import graph_engine as ge
import forensic_ai as fai

app = Flask(__name__)
app.secret_key = "police_investigation_secret_key"

# Database Configuration
db_url = "mysql+pymysql://root:suhani@localhost/miniproject"
engine = create_engine(db_url)

# --- HELPER FUNCTIONS ---

def get_full_logs():
    """Fetches all logs joined with User and IP info for analysis"""
    query = """
        SELECT l.*, u.EMail, i.IPAddress, i.CountryCode, i.RepScore 
        FROM loginattempt l
        LEFT JOIN user u ON l.UserId = u.UserId
        LEFT JOIN ipaddress i ON l.IPId = i.IPId
        ORDER BY l.CreatedAt DESC
    """
    return pd.read_sql(query, engine)

@app.route('/admin-home')
def admin_home():
    with engine.connect() as conn:
        # Use a JOIN to get everything in one go
        query = text("""
            SELECT 
                la.AttemptId, 
                IFNULL(u.EMail, 'Unknown/Attacker'), 
                la.IPId, 
                la.SiteId, 
                la.Success, 
                la.CreatedAt 
            FROM loginattempt la
            LEFT JOIN user u ON la.UserId = u.UserId
            ORDER BY la.AttemptId DESC
        """)
        df = pd.read_sql(query, conn)
        
        # This turns the whole table into a simple list of values
        # Example: [[81, 'user@mail.com', '192...', 4, 1, '10:00'], [...]]
        final_logs = df.values.tolist() 

    return render_template('admin_home.html', logs=final_logs)

# --- ROUTES ---

@app.route('/')
def admin_login():
    return render_template('admin_login.html')

@app.route('/admin-auth', methods=['POST'])
def admin_auth():
    badge_id = request.form.get('badge_id')
    password = request.form.get('password')
    
    if badge_id == "OFFICER_007" and password == "pune_police":
        session['officer'] = badge_id
        return redirect('/admin-home')
    else:
        return "Access Denied: Invalid Badge ID", 403

# 1. GLOBAL INTELLIGENCE PAGE
@app.route('/intel/global')
def global_intel():
    if 'officer' not in session: return redirect('/')
    df = get_full_logs()
    chart = ge.generate_geo_chart(df)
    report, suggestion = fai.analyze_global_threats(df)
    return render_template('admin_global.html', chart=chart, report=report, suggestion=suggestion)

# 2. SITE PRESSURE PAGE
@app.route('/intel/pressure')
def site_pressure():
    if 'officer' not in session: return redirect('/')
    df = get_full_logs()
    # Note: Using the updated function name from graph_engine.py
    chart = ge.generate_site_pressure_chart(df)
    top_site = df['SiteId'].value_counts().idxmax()
    report = f"AI Analysis: Site ID {top_site} is experiencing the highest traffic volume."
    suggestion = "Recommendation: Enable rate-limiting on this specific endpoint."
    return render_template('admin_pressure.html', chart=chart, report=report, suggestion=suggestion)

# 3. USER RISK PAGE
@app.route('/intel/user-risk')
def user_risk():
    if 'officer' not in session: return redirect('/')
    df = get_full_logs()
    flagged_users = df.groupby('UserId').filter(lambda x: x['SiteId'].nunique() > 1)
    
    chart = ge.generate_velocity_chart(df) 
    report, suggestion = fai.analyze_user_risk(flagged_users)
    
    sus_list = flagged_users.head(10).to_dict(orient='records')
    return render_template('admin_user_risk.html', chart=chart, report=report, suggestion=suggestion, sus_list=sus_list)

# 4. IP REPUTATION PAGE
@app.route('/intel/reputation')
def ip_reputation():
    if 'officer' not in session: return redirect('/')
    query = "SELECT * FROM ipaddress WHERE RepScore < 30 ORDER BY RepScore ASC"
    df = pd.read_sql(query, engine)
    risk_list = df.to_dict(orient='records')
    report, suggestion = fai.analyze_reputation(df)
    return render_template('admin_reputation.html', risk_list=risk_list, report=report, suggestion=suggestion)

# 5. AUDIT LOGS PAGE
@app.route('/intel/audit')
def system_audit():
    if 'officer' not in session: return redirect('/')
    df = get_full_logs()
    logs = df.to_dict(orient='records')
    return render_template('admin_audit.html', logs=logs)

@app.route('/intel/alerts')
def security_alerts():
    if 'officer' not in session: return redirect('/')
    
    with engine.connect() as conn:
        # EXECUTE THE PROCEDURE YOU ALREADY CREATED
        conn.execute(text("CALL RunSecurityAudit()"))
        conn.commit()

        # FETCH THE FLAGGED ACTIVITY
        query = """
            SELECT s.*, i.IPAddress, r.RuleName, r.Description
            FROM susact s
            LEFT JOIN ipaddress i ON s.IPId = i.IPId
            LEFT JOIN detectionrule r ON s.RuleId = r.RuleId
            ORDER BY s.DetectedAt DESC
        """
        alerts = pd.read_sql(query, engine).to_dict(orient='records')
    
    return render_template('admin_alerts.html', alerts=alerts)

# --- OFFICER ACTIONS & TOOLS ---

@app.route('/action/tactical-trigger', methods=['POST'])
def tactical_trigger():
    if 'officer' not in session: return redirect('/')
    action_type = request.form.get('action_type')
    flash(f"Tactical Action [{action_type}] initialized successfully. Firewall updated.")
    return redirect(request.referrer)

@app.route('/download/traffic-logs')
def download_traffic_logs():
    if 'officer' not in session: return redirect('/')
    df = get_full_logs()
    
    buffer = io.StringIO()
    df.to_csv(buffer, index=False)
    mem = io.BytesIO()
    mem.write(buffer.getvalue().encode())
    mem.seek(0)
    
    return send_file(mem, mimetype='text/csv', as_attachment=True, download_name='Forensic_Audit_Report.csv')

@app.route('/action/block-ip', methods=['POST'])
def block_ip():
    if 'officer' not in session: return redirect('/')
    ip_addr = request.form.get('ip_address')
    with engine.connect() as conn:
        conn.execute(text("UPDATE ipaddress SET IsBlacklisted = 1 WHERE IPAddress = :ip"), {"ip": ip_addr})
        conn.commit()
    flash(f"IP {ip_addr} has been successfully BLACKLISTED.")
    return redirect(request.referrer)

@app.route('/action/freeze-user', methods=['POST'])
def freeze_user():
    if 'officer' not in session: return redirect('/')
    user_id = request.form.get('user_id')
    email = request.form.get('email')
    with engine.connect() as conn:
        conn.execute(text("UPDATE user SET Status = 'frozen' WHERE UserId = :uid"), {"uid": user_id})
        conn.commit()
    flash(f"User {email} has been FROZEN. Forensic alert sent.")
    return redirect(request.referrer)

def get_full_logs():
    """Fetches all logs joined with current User Status and IP Status"""
    query = """
        SELECT 
            MAX(l.UserId) as UserId, 
            u.EMail, 
            u.Status, 
            i.IPAddress, 
            MAX(i.CountryCode) as CountryCode, 
            MAX(i.RepScore) as RepScore, 
            i.IsBlacklisted, 
            MAX(l.CreatedAt) as CreatedAt, 
            l.SiteId
        FROM loginattempt l
        LEFT JOIN user u ON l.UserId = u.UserId
        LEFT JOIN ipaddress i ON l.IPId = i.IPId
        GROUP BY u.EMail, l.SiteId, i.IPAddress, u.Status, i.IsBlacklisted
        ORDER BY CreatedAt DESC
    """
    return pd.read_sql(query, engine)

@app.route('/logout')
def admin_logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    # host='0.0.0.0' is the key—it opens the "window" for the tunnel
    app.run(host='0.0.0.0', port=5001, debug=True)