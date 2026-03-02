# AI-Powered SOC Analyst Dashboard

A full-stack Security Operations Center (SOC) web application designed to ingest unstructured network logs, detect active cyber threats using Machine Learning, and generate actionable, human-readable incident reports using Generative AI.

## Project Overview

Modern SOC teams are often overwhelmed by log data. This project solves that problem by automating the initial triage process. It parses raw access logs, applies a multi-layered threat detection engine to identify malicious behavior, and utilizes Large Language Models (LLMs) to write technical incident reports, allowing analysts to focus on mitigation rather than manual log reading.

## Key Features

* **Automated Log Ingestion & Parsing:** Capable of intelligently parsing standard CSVs and raw Apache/Nginx unstructured text logs using advanced Regular Expressions and Pandas.
* **Interactive Analytics Dashboard:** A Next.js frontend featuring time-slicing sliders, dynamic data filtering, and interactive visualizations (via Recharts).
* **Automated Incident Reporting:** Generates a 3-part incident response report (Context, Trigger Reason, and Mitigation) for every detected anomaly.
* **Privacy-Preserving Architecture:** Automatically masks and redacts sensitive Personally Identifiable Information (PII) like IP addresses and usernames before sending data to external AI APIs.
* **Historical Threat Tracking:** Persists all uploaded logs, parsed data, and AI reports in a relational database for historical auditing and compliance.

## Tech Stack

* **Frontend:** Next.js (React), Tailwind CSS, Recharts, Lucide Icons
* **Backend:** Python, FastAPI, SQLAlchemy (ORM), Psycopg2
* **Database:** PostgreSQL
* **Machine Learning & AI:** Scikit-Learn (IsolationForest), Google Gemini API (gemini-1.5-flash)
* **Infrastructure:** Docker, Docker Compose

## Architecture Notes

* **Decoupled Microservices:** The application is fully containerized using Docker, separating the frontend, backend, and database into distinct, easily scalable services.
* **Stateless Authentication:** Implements JWT (JSON Web Tokens) and bcrypt password hashing for secure, stateless API authorization.
* **Rate-Limit Management:** The backend implements an intelligent chunking and micro-pause mechanism to batch process LLM requests, ensuring the system stays within external API rate limits without crashing or dropping logs.
* **Hybrid Data Processing:** Uses a custom Regex blueprint for fast parsing, with a safe fallback to Pandas DataFrames for unexpected file structures.

## AI Model & Anomaly Detection Approach

The application does not rely on a single model. Instead, it utilizes a highly scalable, three-phase pipeline to ensure accurate detection and minimize false positives:

1. **Deterministic Rule Matching (Signatures):** The engine first scans the URLs and HTTP methods using advanced Regular Expressions to catch known, common attack vectors. This layer immediately flags threats like SQL Injection (SQLi), Cross-Site Scripting (XSS), and Command Injection / Directory Traversal.

2. **Machine Learning Anomaly Detection (Zero-Day Threats):**
   For novel attacks that evade standard Regex signatures, the system groups traffic by minute-level time buckets and feeds volumetric data (bytes sent/received, requests per minute) into Scikit-Learn's IsolationForest algorithm. This unsupervised machine learning model calculates mathematical outliers, flagging unusual behavior (e.g., data exfiltration or abnormal request spikes) as generic "Behavioral Anomalies".

3. **Generative AI Incident Reporting (Contextualization):**
   Once anomalies are flagged, the data is scrubbed of PII and batched into chunks. These chunks are sent to the Google Gemini 1.5 Flash Large Language Model via strict prompt engineering. The LLM acts as an expert security analyst, interpreting the raw data and returning structured JSON containing the threat context, the specific trigger reason, and actionable mitigation steps.

---

## Local Installation & Setup

The entire application is containerized, making it simple to deploy locally without manual environment or dependency configuration.

### Prerequisites
* Git
* Docker Desktop installed and running.
* A free Google Gemini API Key.

### 1. Clone the Repository
Open your terminal and run the following commands:
```bash
git clone [https://github.com/YOUR_GITHUB_USERNAME/soc-dashboard.git](https://github.com/YOUR_GITHUB_USERNAME/soc-dashboard.git)
cd soc-dashboard
```

### 2. Environment Configuration
Create a `.env` file inside the `backend/` directory to hold your database and API credentials:
```bash
touch backend/.env
```
Open the `backend/.env` file and add the following configuration:
```env
# Database Settings (These match the docker-compose.yml configuration)
DB_HOST=db
DB_PORT=5432
DB_NAME=soc_logs
DB_USER=soc_admin
DB_PASSWORD=supersecretpassword

# AI Credentials (Replace with your actual key)
GEMINI_API_KEY=your_actual_gemini_api_key_here
```

### 3. Build and Run the Application
From the root directory of the project (where the `docker-compose.yml` file is located), start the Docker containers:
```bash
docker-compose up --build
```

## Usage Instructions

Once the terminal indicates that both Uvicorn (Backend) and Next.js (Frontend) are successfully running, you can access the application:

1. **Access the Frontend:** Open your web browser and navigate to http://localhost:3000.
2. **Create an Account:** On your first visit, click "Need an account? Sign up" to create a local admin account.
3. **Upload Logs:** Log in and upload a standard `.txt` or `.csv` access log file. 
4. **View Dashboard:** Once processing is complete, the application will automatically route you to the interactive dashboard.
5. **Access the API Documentation:** To interact directly with the backend endpoints, navigate to the auto-generated Swagger UI at http://localhost:8000/docs.

### Stopping the Application
To gracefully stop the servers and clean up the running containers, press `Ctrl + C` in your terminal, or run:
```bash
docker-compose down
```