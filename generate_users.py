import mysql.connector
import random
from datetime import datetime, timedelta

# --- DATABASE CONNECTION ---
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="suhani",
    database="miniproject"
)
cursor = db.cursor()

# Names and Domains for authenticity
names = ["arjun", "priya", "rohan", "sanya", "amit", "ishita", "kabir", "neha", "vikram", "ananya", "rahul", "diya"]
domains = ["gmail.com", "yahoo.com", "outlook.com", "mitwpu.edu.in", "hotmail.com"]

for i in range(50):
    user_prefix = f"{random.choice(names).lower()}{random.randint(10, 999)}"
    email = f"{user_prefix}@{random.choice(domains)}"
    
    password = f"Secure{random.randint(100, 999)}!" if i % 2 == 0 else "password123"
    
    site_id = random.randint(1, 4)
    
    random_days_back = random.randint(1, 30)
    random_minutes_back = random.randint(0, 1440)
    created_at = datetime.now() - timedelta(days=random_days_back, minutes=random_minutes_back)

    query = """
    INSERT INTO user (EMail, PasswordHash, SiteId, Status, CreatedAt) 
    VALUES (%s, %s, %s, 'active', %s)
    """
    cursor.execute(query, (email, password, site_id, created_at))

db.commit()
print(f"✅ Successfully created 50 users with varied registration dates!")
db.close()
