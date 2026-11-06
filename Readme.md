# Credential Stuffing and Account Takeover Detection System

An Adaptive Cybersecurity Intelligence System designed to monitor multi-domain login activities, detect automated credential stuffing and brute-force attacks in real time, and provide forensic investigation tools for security administrators.

---

## 🚀 Project Overview

Modern web applications face continuous automated threats where attackers leverage compromised credentials from data breaches to breach user accounts across multiple services. This platform addresses these vulnerabilities by moving beyond static password authentication to incorporate:

* **Real-Time IP Geolocation Tracking** via external APIs.
* **Behavioral Risk Scoring & Velocity Analysis** to identify attack spikes.
* **Automated Security Auditing** powered by MySQL database triggers, stored procedures, and user-defined functions.
* **Multi-Domain Support** spanning Social, Banking, E-commerce, and Educational portals.
* **Administrative Forensic Dashboard** built with Flask, Pandas, and Matplotlib.

---

## 🛠️ Tech Stack

* **Backend:** Python (Flask Micro-framework), SQLAlchemy (ORM)
* **Database:** MySQL (Relational DB, Triggers, Stored Procedures, Functions)
* **Data Analysis & Visualization:** Pandas, Matplotlib, Jinja2 Templating
* **Networking & Deployment:** Localhost.run / SSH Reverse Tunneling, Requests API

---

## 📂 Repository File Structure

```text
├── .vscode/               # Editor configurations
├── SS/                    # Project screenshots and documentation assets
├── templates/             # HTML templates for user portals and admin panels
├── admin_panel.py         # Administrative forensic terminal and analytics dashboard
├── app.py                 # Core user-facing Flask app (handles login, signup, IP tracking)
├── attackers.py           # Automated botnet attack simulator for testing detection rules
├── forensic_ai.py         # Threat analysis logic module (global threats, user risk, IP reputation)
├── generate_logins.py     # Script to simulate historical login traffic and attack logs
├── generate_users.py      # Script to populate mock user data
├── graph_engine.py        # Matplotlib visualization engine generating charts for the dashboard
└── README.md              # Project documentation
```

---

## ⚙️ Database Schema & Normalization

The database adheres to **Third Normal Form (3NF)** to ensure data integrity and avoid update anomalies:

1. **`Site` Table:** Stores details of the supported portal networks.
2. **`User` Table:** Manages user credentials, statuses (`active`, `frozen`), and portal associations.
3. **`IPAddress` Table:** Tracks client IP addresses, country codes, reputation scores, and blacklisting status.
4. **`LoginAttempt` Table:** Central audit log recording every login attempt timestamp, success status, and failure reason.
5. **`DetectionRule` & `SusAct` Tables:** Defines threshold rules and records flagged suspicious activities during security audits.

---

## 🚀 Installation & Running the Project

### 1. Prerequisites
* Python 3.x installed
* MySQL Server running locally

### 2. Setup the Database
Create the database in MySQL and execute your DDL/DML scripts:
```sql
CREATE DATABASE miniproject;
USE miniproject;
-- Execute schema setup tables (Site, User, IPAddress, DetectionRule, LoginAttempt, SusAct)
```

### 3. Install Dependencies
```bash
pip install flask pymysql sqlalchemy pandas matplotlib requests
```

### 4. Run the Applications
Open two separate terminal windows to run both the user portal and the administrator forensic dashboard concurrently:

* **Terminal 1: Start User Portal**
  ```bash
  python app.py
  ```
  *(Accessible locally at `http://127.0.0.1:5000`)*

* **Terminal 2: Start Admin Panel**
  ```bash
  python admin_panel.py
  ```
  *(Accessible locally at `http://127.0.0.1:5001` — Login with Badge ID: `OFFICER_007`, Password: `pune_police`)*

---

## 🛡️ Simulating Attacks & Testing

To test the detection mechanisms and populate the admin dashboard with real-time analytics:
```bash
python attackers.py
```
This script simulates a distributed botnet attack trying common passwords across multiple targeted user accounts and spoofing high-risk IPs.

---

## 👥 Authors (Group 4)

* **Suhani Shah** (`1262242212`)
* **Shreya Pandey** (`1262242081`)
* **Sneha Kunnummal** (`1262242233`)
* **Anil Neerati** (`1262243623`)

*Under the guidance of Dr. Sukhada Bhingarkar / Department of Computer Engineering and Technology, MIT World Peace University, Pune.*