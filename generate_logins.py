import mysql.connector
import random
from datetime import datetime, timedelta, time

db = mysql.connector.connect(host="localhost", user="root", password="suhani", database="miniproject")
cursor = db.cursor()

# 1. Get the newly created UserIds
cursor.execute("SELECT UserId, SiteId FROM user")
users = cursor.fetchall()

# 2. Pick 10 unique dates from the last 30 days
today = datetime.now().date()
target_dates = [today - timedelta(days=d) for d in random.sample(range(1, 30), 10)]

# 3. IP Pool of 20 unique addresses
ip_list = [f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" for _ in range(20)]

print("Generating 200 attempts across 10 specific dates with unique times...")

for _ in range(200):
    user = random.choice(users)
    ip = random.choice(ip_list)
    
    # Ensure IP is in the table
    cursor.execute("SELECT IPId FROM ipaddress WHERE IPAddress = %s", (ip,))
    ip_res = cursor.fetchone()
    if not ip_res:
        # Default RepScore 100 for clean data
        cursor.execute("INSERT INTO ipaddress (IPAddress, IsBlacklisted, CountryCode, RepScore) VALUES (%s, 0, 'IN', 100)", (ip,))
        db.commit()
        ipid = cursor.lastrowid
    else:
        ipid = ip_res[0]

    # Success/Failure (30% failure rate)
    success = 1 if random.random() > 0.3 else 0
    reason = "None" if success else "Invalid Credentials"
    
    # --- TIME LOGIC: Pick one of the 10 dates + random time ---
    selected_date = random.choice(target_dates)
    random_time = time(random.randint(0, 23), random.randint(0, 59), random.randint(0, 59))
    timestamp = datetime.combine(selected_date, random_time)

    query = "INSERT INTO loginattempt (TimeStamp, Success, FailureReason, UserId, SiteId, IPId, AttemptCount) VALUES (%s, %s, %s, %s, %s, %s, 1)"
    cursor.execute(query, (timestamp, success, reason, user[0], user[1], ipid))

db.commit()
print("✅ 200 Login attempts created. First AttemptId is 1.")
db.close()
