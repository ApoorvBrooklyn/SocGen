# Security Management Platform Backend

A comprehensive FastAPI-based backend for advanced security management with cybersecurity LLM integration.

## Features

### 🔍 **LLM-Driven CVE Analysis Engine**
- NVD feed integration for real-time CVE data
- LLM-powered vulnerability analysis and summarization
- Business impact assessment and layman explanations
- Automated patch mapping and remediation recommendations

### 🔧 **Automated Vulnerability Scanner Integrator**
- Support for OpenVAS, Nessus, and OSQuery scanners
- Nmap integration for network vulnerability scanning
- LLM correlation of scan results with CVE database
- Real-time scan progress tracking and management

### 📊 **Risk-Based Prioritization**
- CVSS score analysis and severity assessment
- Exploit availability and maturity evaluation
- Asset value and business impact consideration
- LLM-driven prioritization reasoning and timeline suggestions

### 🛠️ **Patch Recommendation Generator**
- OS-specific patch commands (Ubuntu, CentOS, Windows)
- Vendor patch links and release notes
- Rollback procedures and verification steps
- Confidence scoring and explainability

### 🎫 **Change Management Ticket Generator**
- JIRA, ServiceNow, and GitHub Issues integration
- Automated ticket creation with CVE summaries
- Risk assessment and remediation planning
- Due date calculation and owner assignment

### 📧 **Email & Report Automation**
- Executive summaries for management
- Technical briefs for system administrators
- Automated stakeholder notifications
- Customizable report templates

### ✅ **Patch Verification Module**
- Post-deployment verification scanning
- Log analysis and success confirmation
- Automated ticket closure
- Remediation effectiveness tracking

### 🤖 **LLM Chat Assistant for SOC Teams**
- Real-time CVE queries and analysis
- Context-rich security recommendations
- Interactive vulnerability assessment
- Knowledge base integration

## Architecture

```
backend/
├── app/
│   ├── core/           # Core functionality
│   │   ├── config.py   # Configuration management
│   │   ├── database.py # JSON database service
│   │   └── logging.py  # Structured logging
│   ├── services/       # Business logic services
│   │   ├── llm_service.py           # LLM integration
│   │   ├── cve_analysis.py          # CVE analysis engine
│   │   └── vulnerability_scanner.py # Scanner integration
│   └── api/           # API endpoints
│       └── v1/
│           ├── api.py  # Main API router
│           └── endpoints/
├── data/              # JSON data storage
├── logs/              # Application logs
├── main.py           # FastAPI application
├── start.py          # Startup script
└── requirements.txt  # Dependencies
```

## Installation

### Prerequisites
- Python 3.8+
- 4GB+ RAM (for LLM models)
- 10GB+ disk space

### Setup

1. **Clone and navigate to backend directory**
```bash
cd backend
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment** (optional)
```bash
# Copy and edit configuration
cp .env.example .env
# Edit .env with your settings
```

### Running the Backend

#### Option 1: Using the startup script
```bash
python start.py
```

#### Option 2: Using uvicorn directly
```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

#### Option 3: Using Python directly
```bash
python main.py
```

The backend will be available at:
- API: http://localhost:8000
- Documentation: http://localhost:8000/docs
- Health Check: http://localhost:8000/health

## API Endpoints

### Core Endpoints
- `GET /` - Root endpoint with API information
- `GET /health` - Health check and system status
- `GET /docs` - Interactive API documentation

### CVE Analysis
- `GET /api/v1/cve/` - List all CVEs
- `GET /api/v1/cve/{cve_id}` - Get specific CVE
- `POST /api/v1/cve/analyze` - Analyze CVE with LLM
- `POST /api/v1/cve/sync/recent` - Sync recent CVEs from NVD

### Vulnerability Scanning
- `POST /api/v1/scan/` - Start vulnerability scan
- `GET /api/v1/scan/{scan_id}/status` - Get scan status
- `GET /api/v1/scan/scanners/status` - Get scanner status

### Patch Management
- `POST /api/v1/patches/recommend` - Generate patch recommendations
- `POST /api/v1/patches/deploy` - Deploy patches
- `GET /api/v1/patches/history` - Get patch history

### Chat Assistant
- `POST /api/v1/chat/sessions` - Create chat session
- `POST /api/v1/chat/messages` - Send message to AI
- `GET /api/v1/chat/sessions` - List chat sessions

### Reports
- `POST /api/v1/reports/generate` - Generate security report
- `GET /api/v1/reports/templates` - Get report templates
- `GET /api/v1/reports/history` - Get report history

### LLM Management
- `GET /api/v1/llm/status` - Get LLM service status
- `POST /api/v1/llm/test` - Test LLM with prompts
- `GET /api/v1/llm/models` - List available models

## Configuration

### Environment Variables

```bash
# Environment
ENVIRONMENT=development
DEBUG=true
LOG_LEVEL=info

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000

# LLM Configuration
LLM_MODEL_NAME=microsoft/DialoGPT-medium
LLM_DEVICE=auto
LLM_MAX_LENGTH=512

# External APIs
NVD_API_KEY=your_nvd_api_key
GITHUB_TOKEN=your_github_token
JIRA_URL=https://your-company.atlassian.net
```

### LLM Models

The backend supports various LLM models:
- `microsoft/DialoGPT-medium` (default) - Conversational AI
- `microsoft/DialoGPT-large` - Larger conversational model
- `facebook/opt-1.3b` - Open Pre-trained Transformer

## Data Storage

The backend uses JSON files for data persistence:
- `data/cves.json` - CVE records
- `data/scan_results.json` - Vulnerability scan results
- `data/patch_recommendations.json` - Patch recommendations
- `data/chat_sessions.json` - Chat sessions
- `data/reports.json` - Generated reports

## Security Features

### LLM-Driven Analysis
- CVE impact assessment and business risk evaluation
- Automated exploit method identification
- Layman explanations for management reporting
- Contextual remediation recommendations

### Vulnerability Correlation
- Cross-reference with multiple threat intelligence sources
- GitHub security advisory integration
- Exploit database correlation
- Real-world attack pattern analysis

### Risk Prioritization
- CVSS score normalization and weighting
- Asset criticality assessment
- Exploit availability and maturity scoring
- Business impact quantification

## Development

### Adding New Features

1. **Create service** in `app/services/`
2. **Add API endpoints** in `app/api/v1/endpoints/`
3. **Register router** in `app/api/v1/api.py`
4. **Update documentation**

### Testing

```bash
# Run basic health check
curl http://localhost:8000/health

# Test LLM service
curl -X POST http://localhost:8000/api/v1/llm/test \
  -H "Content-Type: application/json" \
  -d '{"test_prompts": ["What is CVE-2024-0001?"]}'

# Start a vulnerability scan
curl -X POST http://localhost:8000/api/v1/scan/ \
  -H "Content-Type: application/json" \
  -d '{"target": "127.0.0.1", "scanner_type": "nmap"}'
```

### Logging

Structured logging with multiple levels:
- Application logs: `logs/security_platform.log`
- Error logs: `logs/errors.log`
- Security events: Structured JSON format

## Deployment

### Production Considerations

1. **Security**
   - Change default SECRET_KEY
   - Configure CORS origins
   - Enable HTTPS
   - Set up authentication

2. **Performance**
   - Use production ASGI server (Gunicorn + Uvicorn)
   - Configure LLM model caching
   - Implement rate limiting
   - Set up monitoring

3. **Scalability**
   - Use PostgreSQL for production database
   - Implement Redis for caching
   - Set up load balancing
   - Configure auto-scaling

### Docker Deployment

```bash
# Build image
docker build -t security-platform-backend .

# Run container
docker run -p 8000:8000 security-platform-backend
```

## Troubleshooting

### Common Issues

1. **LLM Model Loading Errors**
   - Ensure sufficient RAM (4GB+)
   - Check CUDA availability for GPU acceleration
   - Verify model name and availability

2. **CVE Sync Issues**
   - Check NVD API rate limits
   - Verify internet connectivity
   - Ensure API key is valid

3. **Scanner Integration Problems**
   - Verify scanner installation and configuration
   - Check network connectivity to target systems
   - Ensure proper permissions for scanning

### Performance Optimization

1. **LLM Performance**
   - Use GPU acceleration when available
   - Adjust model parameters for speed vs quality
   - Implement response caching

2. **Database Performance**
   - Regular data cleanup and archiving
   - Optimize JSON file sizes
   - Consider database indexing

## Contributing

1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit pull request

## License

This project is licensed under the MIT License.

## Support

For issues and questions:
- Check the documentation
- Review API endpoints at `/docs`
- Check logs in `logs/` directory
- Create GitHub issue for bugs 