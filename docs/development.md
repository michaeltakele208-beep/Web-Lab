# VADL Developer & Operator Guide

## 1. Prerequisites

* **Python**: Version 3.11 or 3.12 (explicitly tested on 3.11.9 and 3.12).
* **PowerShell**: Windows PowerShell 5.1+ or PowerShell Core 7+.
* **Docker & Docker Compose**: Docker Engine 24.0+ / Docker Desktop (optional for local non-container development).

---

## 2. Windows PowerShell Setup

### 2.1 Virtual Environment Creation & Activation
```powershell
# Create an isolated Python virtual environment
python -m venv .venv

# Activate the virtual environment
.\.venv\Scripts\Activate.ps1
```

### 2.2 Installing Dependencies
```powershell
# Upgrade pip to latest version
python -m pip install --upgrade pip

# Install production and development dependencies
pip install -r requirements-dev.txt
```

### 2.3 Environment Variable Setup
```powershell
# Copy the example environment template
Copy-Item .env.example .env

# Generate a cryptographically secure 32-byte secret key for production testing
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## 3. Database Management & Migrations

VADL uses Flask-Migrate (Alembic) alongside Flask-SQLAlchemy.

```powershell
# Set Flask application context
$env:FLASK_APP = "run.py"

# Apply all database migrations to local development SQLite
flask db upgrade

# Generate a new migration script if models are modified
flask db migrate -m "Description of model change"
```

---

## 4. Administrative Account Provisioning (Out-of-Band CLI)

To preserve separation of privilege, initial administrator accounts cannot be self-registered via public endpoints. They must be provisioned through server CLI commands:

### 4.1 Create Initial Administrator
```powershell
$env:FLASK_APP = "run.py"
flask user create-admin --email admin@vadl.local --name "Security Administrator" --password "AdminSecurePass123!@"
```

### 4.2 Promote Existing User to Security Analyst or Admin
```powershell
flask user promote --email analyst@vadl.local --role security_analyst
```

### 4.3 Inspect Registered Users
```powershell
flask user list
```

---

## 5. Running the Application

### 5.1 Local Development Server (Bound strictly to 127.0.0.1)
```powershell
python run.py
```
Access the application dashboard at: `http://127.0.0.1:5000`

### 5.2 Running via Docker Compose
When Docker is available on the host:
```powershell
# Build and start container in detached mode
docker compose up -d --build

# View container status
docker compose ps

# Stop containers and teardown isolated bridge network
docker compose down
```

---

## 6. Testing & Quality Assurance

### 6.1 Running Automated Unit & Integration Tests (pytest)
```powershell
# Run the complete test suite (41 tests)
pytest

# Run tests with code coverage analysis
pytest --cov=app --cov-report=term-missing
```

### 6.2 Linting & Formatting (Ruff)
```powershell
# Run static style and import checks
ruff check .

# Automatically apply safe fixes and import sorting
ruff check --fix .

# Verify formatting
ruff format --check .

# Format code files
ruff format .
```

### 6.3 Static Application Security Testing (Bandit)
```powershell
# Run Bandit security scan across the application codebase
bandit -r app -f screen

# Generate a machine-readable JSON security report
bandit -r app -f json -o reports/bandit-report.json
```

### 6.4 Dependency Vulnerability Auditing (pip-audit)
```powershell
# Audit dependencies against known CVE and PyPA advisory databases
pip-audit -r requirements.txt
```
