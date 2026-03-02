# Hybrid AI SIEM Dashboard

## Overview
This project is a Full-Stack Security Information and Event Management (SIEM) dashboard designed for Security Operations Center (SOC) analysts. It processes raw web server logs, identifies critical vulnerabilities using a hybrid detection engine, and automatically generates incident response reports using Large Language Models (LLMs).

The system prioritizes data privacy by utilizing local machine learning for primary detection and heavily sanitizing data before any third-party AI processing occurs.

## Key Features

* **Machine Learning Anomaly Detection**
  * Utilizes Scikit-Learn's Isolation Forest algorithm to detect zero-day behavioral anomalies based on request volume, payload size, and traffic patterns.
* **Signature-Based Threat Detection**
  * Employs strict regular expressions (Regex) to instantly identify known attack vectors, including SQL Injection (SQLi), Cross-Site Scripting (XSS), Command Injection (RCE), and Unauthorized Sensitive Path Access.
* **Volumetric Attack Analysis**
  * Groups time-series data into minute-level buckets to accurately detect automated Brute Force attacks, Directory Enumeration, and Vulnerability Scanning (404 Storms).
* **Interactive SOC Dashboard**
  * A responsive Next.js frontend featuring custom data visualization, dynamic time-range scrubbing, and granular threat filtering.

## Technology Stack

### Frontend
* Next.js (React Framework)
* Tailwind CSS (Styling)
* Recharts (Data Visualization)
* Lucide React (Iconography)

### Backend
* Python
* Pandas & NumPy (Data processing and feature engineering)
* Scikit-Learn (Isolation Forest ML model)
* Google Generative AI SDK (Gemini API integration)

## Architecture Notes
To prevent API rate limiting and token exhaustion, the backend implements a chunking methodology. Anomalies are scrubbed of identifiable information, chunked into specific batch sizes, and sent to the LLM. The responses are then parsed, unmasked, and mapped back to the relational database locally before being served to the frontend UI.

This privacy-safe AI processing occurs in four distinct steps once anomalies are detected:

1. **Local Data Scrubbing:** Before any data leaves the local server, all Personally Identifiable Information (PII) such as IP addresses and Usernames are stripped from the logs and replaced with `[REDACTED_IP]` and `[USER_LOGIN]` placeholder tags.
2. **Batch Chunking:** The scrubbed anomalies are divided into chunks (e.g., batches of 100). This ensures the payload size remains well within the LLM's context window, preventing dropped connections or truncated JSON responses.
3. **AI Template Generation:** The LLM is prompted to analyze the chunks and generate generalized, 3-part incident response templates (Context, Trigger Reason, Mitigation) that utilize the placeholder tags.
4. **Local Data Re-injection:** Once the AI templates are returned to the local server, the Python engine intercepts the response and rapidly injects the real, unmasked IP addresses and Usernames back into the text before saving the final reports to the database.

## Installation and Setup

### Prerequisites
* Node.js (v18 or higher)
* Python (v3.9 or higher)
* A valid Google Gemini API Key

### Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows use: venv\Scripts\activate
   ```
3. Install the required Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Create a `.env` file in the backend directory and add your API key:
   ```env
   GEMINI_API_KEY=your_api_key_here
   ```
5. Start the backend server:
   ```bash
   python main.py
   ```

### Frontend Setup
1. Navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install the required Node dependencies:
   ```bash
   npm install
   ```
3. Start the development server:
   ```bash
   npm run dev
   ```

## Usage
1. Open a web browser and navigate to `http://localhost:3000`.
2. Authenticate using your credentials.
3. Click "Upload New" to ingest a raw Apache or Nginx access log file (TXT, CSV, or LOG format).
4. The backend will parse the file, run the isolation forest model, match threat signatures, and batch-process the anomalies through the LLM.
5. Utilize the visual time-range slider and filter dropdowns to isolate specific threat events and review the automated incident response mitigation steps.