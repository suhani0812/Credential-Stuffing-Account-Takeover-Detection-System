from flask import Flask, render_template, request, redirect, url_for, session, flash
import pandas as pd
from sqlalchemy import create_engine, text
from datetime import datetime
import requests

app = Flask(__name__)
app.secret_key = "user_forensics_key"

# Database Configuration
db_url = "mysql+pymysql://root:suhani@localhost/miniproject"
engine = create_engine(db_url)

def get_client_ip():
    # Checks if the attack script sent a fake IP, otherwise uses the real one
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For')
    return request.remote_addr if request.remote_addr != '127.0.0.1' else '172.16.0.45'

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/login-process/<int:site_id>', methods=['POST'])
def login_process(site_id):
    email = request.form.get('u_email')
    password = request.form.get('u_pass')
    current_ip = get_client_ip()

    with engine.connect() as conn:
        # 1. Fetch user details
        user_query = text("""
            SELECT UserId, PasswordHash, Status 
            FROM user 
            WHERE EMail = :email AND SiteId = :site
        """)
        user_row = conn.execute(user_query, {"email": email, "site": site_id}).fetchone()

        # 2. Get IP ID (Handle New/Foreign IPs immediately)
        ip_query = text("SELECT IPId FROM ipaddress WHERE IPAddress = :ip")
        ip_row = conn.execute(ip_query, {"ip": current_ip}).fetchone()
        
        if ip_row:
            ip_id = ip_row[0]
        else:
            # If IP doesn't exist, detect country and insert it
            try:
                # 1. Try to get the country from the API
                response = requests.get(f'http://ip-api.com/json/{current_ip}', timeout=2)
                api_data = response.json()
                
                # 2. Check if the API actually succeeded
                if api_data.get('status') == 'success':
                    detected_country = api_data.get('countryCode', 'IN') # Default to IN if successful but code missing
                else:
                    # If it's a local/private IP, the API returns "fail"
                    detected_country = 'IN' if current_ip.startswith('192.168') or current_ip == '127.0.0.1' else '??'
            except:
                # Fallback if the internet is down or API is blocked
                detected_country = 'IN'

            # 3. Insert into database
            new_ip_stmt = text("""
                INSERT INTO ipaddress (IPAddress, CountryCode, IsBlacklisted, RepScore) 
                VALUES (:ip, :country, 0, 100)
            """)
            result = conn.execute(new_ip_stmt, {"ip": current_ip, "country": detected_country})
            conn.commit()
            ip_id = result.lastrowid

        # 3. Determine Login Success
        success = 1 if (user_row and user_row.PasswordHash == password) else 0
        user_id = user_row.UserId if user_row else None

        # 4. SECURITY CHECK: Check if account is FROZEN
        if success == 1 and user_row.Status == 'frozen':
            conn.execute(text("""
                INSERT INTO loginattempt (UserId, IPId, SiteId, Success, CreatedAt) 
                VALUES (:uid, :ipid, :sid, 0, NOW())
            """), {"uid": user_id, "ipid": ip_id, "sid": site_id})
            conn.commit()
            return render_template('frozen.html', user_id=user_id), 403

        # 5. Log the Attempt
        log_query = text("""
            INSERT INTO loginattempt (UserId, IPId, SiteId, Success, CreatedAt) 
            VALUES (:uid, :ipid, :sid, :succ, NOW())
        """)
        result = conn.execute(log_query, {"uid": user_id, "ipid": ip_id, "sid": site_id, "succ": success})
        attempt_id = result.lastrowid
        conn.commit()

        if success:
            session['user_id'] = user_id
            session['user_email'] = email
            session['attempt_id'] = attempt_id
            
            templates = {1: 'social_home.html', 2: 'bank_home.html', 3: 'shop_home.html', 4: 'edu_home.html'}
            return render_template(templates.get(site_id, 'login.html'))
        else:
            return render_template('invalid.html'), 401

@app.route('/logout')
def logout():
    attempt_id = session.get('attempt_id')
    if attempt_id:
        with engine.connect() as conn:
            query = text("UPDATE loginattempt SET LogoutAt = NOW() WHERE AttemptId = :aid")
            conn.execute(query, {"aid": attempt_id}) 
            conn.commit()
    
    session.clear()
    return redirect('/')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('u_email')
        new_pass = request.form.get('u_new_pass')
        
        with engine.connect() as conn:
            query = text("UPDATE user SET PasswordHash = :pw WHERE EMail = :email")
            conn.execute(query, {"pw": new_pass, "email": email})
            conn.commit()
        return "Password Updated! <a href='/'>Go Login</a>"
    
    return render_template('forgot_password.html')

@app.route('/signup-process', methods=['POST'])
def signup_process():
    email = request.form.get('u_email')
    password = request.form.get('u_pass')
    site_id = request.form.get('u_site')
    
    try:
        with engine.connect() as conn:
            query = text("INSERT INTO user (EMail, PasswordHash, SiteId, Status, CreatedAt) VALUES (:e, :p, :s, 'active', NOW())")
            conn.execute(query, {"e": email, "p": password, "s": site_id})
            conn.commit()
        
        # This sends a success message to the next page
        flash("Account created successfully! Please login.", "success")
        return redirect('/') # Redirect to login (home)
        
    except Exception as e:
        # If the email is a duplicate or database is down
        flash("Registration failed. This email might already be registered.", "danger")
        return redirect('/signup')

if __name__ == '__main__':
    # host='0.0.0.0' is the key—it opens the "window" for the tunnel
    app.run(host='0.0.0.0', port=5000, debug=True)