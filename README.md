# CVSS Server v1.0 - Complete Vulnerability Assessment System

[![Python](https://img.shields.io/badge/Python-3.12+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Deploy](https://img.shields.io/badge/Deploy-Railway-purple.svg)](https://railway.app)

A comprehensive web-based **Common Vulnerability Scoring System (CVSS) v3.1** calculator and dashboard with advanced features including user authentication, document processing, and collaborative evaluation management.

## 🚀 Live Demo

**Production URL**: [https://cvss-server-v10-production.up.railway.app/](https://cvss-server-v10-production.up.railway.app/)

## ✨ Key Features

### 🔐 **Complete Authentication System**
- **User Registration & Login**: Secure account creation and authentication
- **Session Management**: HttpOnly cookies with 7-day expiration
- **Password Security**: SHA256 hashing with unique salt per user
- **User Profiles**: Personal dashboards and evaluation tracking

### 📊 **CVSS v3.1 Scoring Engine**
- **Official v3.1 Specification**: Accurate CVSS base score calculations
- **Interactive Metrics**: Attack Vector, Attack Complexity, Privileges Required, etc.
- **Severity Classification**: Critical, High, Medium, Low, None
- **Vector Generation**: Automatic CVSS vector string creation

### 📄 **Intelligent Document Processing**
- **Multi-format Support**: Word (.docx) and PDF document analysis
- **Automatic Metric Detection**: AI-powered extraction of CVSS metrics from documents
- **Smart Pre-filling**: Forms automatically populated with detected values
- **Pattern Recognition**: Advanced regex-based vulnerability pattern matching

### 👥 **Collaborative Dashboard**
- **Team Visibility**: View all team members' evaluations
- **Personal Filtering**: Switch between global and personal views
- **Real-time Analytics**: Live charts and severity distribution
- **Evaluation Tracking**: Complete audit trail with user attribution

### 🎨 **Modern User Interface**
- **Responsive Design**: Works perfectly on desktop and mobile
- **Gradient Styling**: Beautiful color-coded severity indicators
- **Interactive Elements**: Smooth animations and hover effects
- **Accessibility**: Clean, intuitive navigation

## 🛠️ Technology Stack

### **Backend**
- **Python 3.12**: Core application language
- **HTTP Server**: Built-in `http.server.ThreadingHTTPServer`
- **SQLite**: Embedded database for data persistence
- **Standard Library**: Minimal external dependencies

### **Frontend**
- **HTML5**: Semantic markup and modern structure
- **CSS3**: Advanced styling with gradients and animations
- **Vanilla JavaScript**: Interactive functionality without frameworks
- **Responsive Design**: Mobile-first approach

### **Document Processing**
- **python-docx**: Microsoft Word document parsing
- **PyPDF2**: PDF text extraction
- **pdfplumber**: Enhanced PDF processing
- **Regular Expressions**: Pattern matching for metric detection

### **Deployment**
- **Railway**: Cloud hosting platform
- **GitHub**: Version control and CI/CD
- **SQLite**: Production database

## 🚀 Quick Start

### **Prerequisites**
- Python 3.12 or higher
- Git

### **Local Installation**

```bash
# Clone the repository
git clone https://github.com/ushio2580/CVSS-Server-v1.0.git
cd CVSS-Server-v1.0

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the server
python server.py
```

The application will be available at `http://localhost:8000`

### **First Time Setup**
1. **Register**: Create your account at `/register`
2. **Login**: Sign in with your credentials
3. **Evaluate**: Start assessing vulnerabilities
4. **Upload Documents**: Try the document processing feature
5. **Dashboard**: View team evaluations and analytics

## 📖 User Guide

### **Authentication**
- **Registration**: Create account with email, password, and full name
- **Login**: Secure authentication with session management
- **Logout**: Clean session termination

### **Vulnerability Evaluation**
1. **Manual Entry**: Fill CVSS metrics manually
2. **Document Upload**: Upload Word/PDF for automatic analysis
3. **Review Results**: Verify detected metrics
4. **Submit**: Save evaluation to database

### **Dashboard Features**
- **All Users View**: See all team evaluations (default)
- **My Evaluations**: Filter to personal assessments only
- **Severity Charts**: Visual distribution of vulnerability severities
- **Top Evaluations**: Highest-scoring vulnerabilities
- **User Attribution**: See who evaluated each vulnerability

### **Document Processing**
- **Supported Formats**: .docx, .pdf
- **Automatic Detection**: CVSS metrics extracted automatically
- **Manual Override**: Adjust detected values as needed
- **Pattern Recognition**: Recognizes common vulnerability descriptions

## 🔧 API Endpoints

### **Authentication**
- `GET /login` - Login page
- `POST /login` - User authentication
- `GET /register` - Registration page
- `POST /register` - User registration
- `GET /logout` - User logout

### **Core Application**
- `GET /` - Main evaluation form (requires auth)
- `POST /evaluate` - Submit new evaluation (requires auth)
- `GET /dashboard` - Analytics dashboard (requires auth)
- `GET /dashboard?show_all=true` - Global view
- `GET /dashboard?show_all=false` - Personal view

### **API Endpoints**
- `GET /api/dashboard/summary` - JSON dashboard data
- `GET /api/vulns` - List all evaluations
- `GET /api/vulns/<id>` - Get specific evaluation
- `GET /api/export/csv` - Export data as CSV

## 🚀 Deployment

### **Railway Deployment (Recommended)**

1. **Fork** this repository to your GitHub account
2. **Sign up** for [Railway](https://railway.app)
3. **Connect** your GitHub repository
4. **Deploy** - Railway will automatically detect Python and deploy

**Environment Variables** (Optional):
- `HOST`: `0.0.0.0` (default)
- `PORT`: `8000` (default)

### **Alternative Deployment Options**

#### **Render**
```yaml
# render.yaml
services:
  - type: web
    name: cvss-server
    env: python
    buildCommand: pip install -r requirements.txt
    startCommand: python server.py
```

#### **Heroku**
```bash
# Procfile
web: python server.py

# runtime.txt
python-3.12.0
```

## 📊 CVSS Severity Levels

| Severity | Score Range | Color | Description |
|----------|-------------|-------|-------------|
| **Critical** | 9.0-10.0 | 🔴 Red | Immediate action required |
| **High** | 7.0-8.9 | 🟠 Orange | Address within 24 hours |
| **Medium** | 4.0-6.9 | 🟡 Yellow | Address within 1 week |
| **Low** | 0.1-3.9 | 🟢 Green | Address within 1 month |
| **None** | 0.0 | ⚪ Gray | No impact |

## 📁 Project Structure

```
CVSS-Server-v1.0/
├── server.py              # Main application server
├── document_processor.py   # Document analysis engine
├── cvss.py                # CVSS calculation logic
├── requirements.txt        # Python dependencies
├── runtime.txt            # Python version specification
├── Procfile               # Deployment configuration
├── README.md              # This documentation
├── LICENSE                # MIT License
└── .gitignore            # Git ignore rules
```

## 🔒 Security Features

- **Password Hashing**: SHA256 with unique salt per user
- **Session Security**: HttpOnly cookies with expiration
- **SQL Injection Protection**: Parameterized queries
- **Input Validation**: Comprehensive data sanitization
- **CSRF Protection**: Session-based request validation

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### **Development Guidelines**
- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation as needed
- Ensure backward compatibility

## 📝 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **CVSS v3.1 Specification**: [FIRST.org](https://www.first.org/cvss/)
- **Python Community**: For excellent standard library
- **Railway**: For seamless deployment platform
- **Open Source Contributors**: For various Python packages

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/ushio2580/CVSS-Server-v1.0/issues)
- **Discussions**: [GitHub Discussions](https://github.com/ushio2580/CVSS-Server-v1.0/discussions)
- **Email**: Contact through GitHub profile

## 🔄 Version History

- **v1.0.0** - Complete system with authentication, document processing, and collaborative features
- **v0.9.0** - Basic CVSS calculator with dashboard
- **v0.8.0** - Initial release with core functionality

---

**Made with ❤️ for the cybersecurity community**

[![GitHub stars](https://img.shields.io/github/stars/ushio2580/CVSS-Server-v1.0?style=social)](https://github.com/ushio2580/CVSS-Server-v1.0/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/ushio2580/CVSS-Server-v1.0?style=social)](https://github.com/ushio2580/CVSS-Server-v1.0/network)