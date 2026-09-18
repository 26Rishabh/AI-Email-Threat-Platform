# AI-Powered Email Threat Detection & Forensic Intelligence Platform

An AI-powered cybersecurity platform for analyzing suspicious emails using email header forensics, SPF/DKIM/DMARC authentication analysis, machine-learning-based threat detection, URL analysis, IP intelligence, risk assessment, case management, and automated forensic reporting.

---

## Overview

Email-based attacks such as phishing, impersonation, credential theft, and malicious links are common cybersecurity threats.

This platform allows a user or security analyst to upload a suspicious `.eml` email and perform a structured investigation.

The system extracts email evidence, analyzes authentication and threat indicators, applies a machine learning model, performs basic IP intelligence, calculates a risk assessment, stores the investigation as a case, and generates a forensic PDF report.

---

## Screenshots

### Login Page

![Login Page](docs/screenshots/login.png)

> More screenshots can be added as the project develops.

---

## Key Features

- User registration and authentication
- Secure password hashing using bcrypt
- JWT-based authentication
- Suspicious `.eml` email upload
- Email header analysis
- SPF, DKIM and DMARC analysis
- URL and domain analysis
- Machine-learning-based phishing/threat detection
- IP intelligence and basic IP geolocation
- Threat indicator extraction
- Risk score calculation
- Evidence correlation
- Case management
- User-specific case isolation
- Automated forensic PDF report generation
- REST API with FastAPI
- Cloud deployment

---

## How It Works

```text
Suspicious Email (.eml)
          |
          v
     Email Parsing
          |
          v
     Header Analysis
          |
     +----+----+----------+
     |         |          |
     v         v          v
    SPF       DKIM       DMARC
     |         |          |
     +---------+----------+
               |
               v
      URL / Domain Analysis
               |
               v
       ML Threat Detection
               |
               v
        IP Intelligence
               |
               v
        Risk Assessment
               |
               v
        Case Management
               |
               v
       Forensic PDF Report