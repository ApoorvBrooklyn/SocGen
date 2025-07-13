# Security Management Platform

A modern, full-stack security management platform for real-time vulnerability monitoring, patch recommendations, risk analysis, and reporting.

**Frontend:** React + TypeScript + TailwindCSS  
**Backend:** FastAPI (Python) + LLM integration  
**Vulnerable Server:** Flask-based intentionally vulnerable app for testing/demo

---

## Features

- **Real-Time Dashboard:**
  - Live updates of CVEs, active scans, risk scores, and system health.
- **Vulnerability Management:**
  - View, analyze, and prioritize vulnerabilities with LLM-powered insights.
- **Patch Recommendations:**
  - Automated/manual patch guidance, deployment tracking, and verification.
- **Risk Prioritization:**
  - Dynamic risk scoring based on severity, exploitability, and business impact.
- **Reports:**
  - Generate, preview, download, and email security reports. View report history.
- **Simulated Vulnerabilities:**
  - Generate and store sample vulnerabilities for testing and demo purposes.
- **System Reset:**
  - Clear all vulnerability data while preserving session, chat, and report history.
- **Vulnerable Server (Demo):**
  - Run an intentionally vulnerable Flask app to test scanning, exploitation, and remediation features.

---

## Project Structure

```
SG/
  backend/         # FastAPI backend
    app/
      api/v1/      # API endpoints
      core/        # Config, DB, logging
      services/    # Business logic
      data/        # JSON data files
    main.py        # FastAPI entrypoint
    requirements.txt
  project/         # React frontend
    src/
      components/  # React components
      services/    # API calls
      types/       # TypeScript types
    package.json
  vulnerable-server/ # Optional vulnerable app for testing
    app.py         # Flask vulnerable app
    requirements.txt
    test_attacks.py
    uploads/
    vuln_app.db
```

---

## Getting Started

### Prerequisites
- Python 3.9+
- Node.js 18+
- npm or yarn
- (Optional) Docker

---

### Backend Setup (FastAPI)

1. **Install dependencies:**
   ```bash
   cd backend
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Run the backend server:**
   ```bash
   uvicorn main:app --reload --host 0.0.0.0 --port 8000
   ```
3. **(Optional) Generate sample data:**
   ```bash
   python create_sample_scans.py
   python create_sample_patches.py
   ```
4. **API Docs:**  
   Visit [http://localhost:8000/docs](http://localhost:8000/docs)

---

### Frontend Setup (React)

1. **Install dependencies:**
   ```bash
   cd project
   npm install
   ```
2. **Run the frontend:**
   ```bash
   npm run dev
   ```
   The app will be available at [http://localhost:5173](http://localhost:5173) (or as shown in the terminal).

---

### Vulnerable Server Setup (Optional)

The `vulnerable-server/` directory contains a Flask-based intentionally vulnerable web application for testing the platform's scanning, exploitation, and remediation features.

1. **Install dependencies:**
   ```bash
   cd vulnerable-server
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
2. **Run the vulnerable server:**
   ```bash
   python app.py
   ```
   The vulnerable app will be available at [http://localhost:5000](http://localhost:5000)

3. **(Optional) Run sample attacks/tests:**
   ```bash
   python test_attacks.py
   ```

---

### Configuration

- **Backend API URL:**  
  The frontend expects the backend at `http://localhost:8000` by default.  
  To change, edit `project/src/services/api.ts`.
- **Environment Variables:**  
  See `backend/app/core/config.py` for backend config options.

---

## Usage

- **Dashboard:**  
  View real-time stats, refresh, or reset system data.
- **CVE Analysis:**  
  Browse, search, and analyze vulnerabilities.
- **Patch Recommendations:**  
  Get and deploy patch guidance for prioritized CVEs.
- **Reports:**  
  Generate, preview, download, and email security reports.
- **Simulate Data:**  
  Use backend scripts to generate demo vulnerabilities and scans.
- **Vulnerable Server:**  
  Use the vulnerable app to test scanning, exploitation, and patching workflows end-to-end.

---

## Development

- **Backend:**  
  - All API code in `backend/app/api/v1/endpoints/`
  - Business logic in `backend/app/services/`
  - Data stored in JSON files in `backend/data/` (for demo/testing)
- **Frontend:**  
  - Main app in `project/src/App.tsx`
  - Components in `project/src/components/`
  - API calls in `project/src/services/api.ts`
- **Testing:**  
  - Backend: Add tests in `backend/`
  - Frontend: Add tests in `project/src/`
  - Vulnerable server: Add/modify attacks in `vulnerable-server/test_attacks.py`

---

## Contributing

1. Fork the repo and create your branch.
2. Make your changes with clear commit messages.
3. Ensure all tests pass.
4. Submit a pull request.

---

## License

[MIT](LICENSE)

---

## Acknowledgements

- [FastAPI](https://fastapi.tiangolo.com/)
- [React](https://react.dev/)
- [TailwindCSS](https://tailwindcss.com/)
- [OpenAI](https://openai.com/) (for LLM integration)
- [Flask](https://flask.palletsprojects.com/) (for the vulnerable server)

---

## Contact

For questions, issues, or feature requests, please open an issue or contact the maintainer.

---

**Enjoy managing your security posture with real-time insights and automation!** 