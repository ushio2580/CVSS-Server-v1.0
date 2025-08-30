# CVSS v3.1 Scoring System

A web-based Common Vulnerability Scoring System (CVSS) v3.1 calculator and dashboard built with Python standard library and SQLite.

## Features

- **CVSS v3.1 Base Score Calculation**: Calculate CVSS scores using the official v3.1 specification
- **Interactive Web Interface**: Modern, responsive UI with gradient backgrounds and severity-based color coding
- **Dashboard**: Visual analytics with charts and metrics for vulnerability assessments
- **API Endpoints**: RESTful API for programmatic access
- **Data Export**: Export evaluations to CSV format
- **No External Dependencies**: Uses only Python standard library

## Local Development

### Prerequisites
- Python 3.7 or higher

### Running Locally
```bash
# Clone the repository
git clone <your-repo-url>
cd cvss_server_project

# Run the server
python server.py
```

The application will be available at `http://localhost:8000`

## Deployment Options

### Option 1: Render (Recommended for Backend)

Render is perfect for hosting the Python backend server.

#### Steps:
1. **Fork/Clone** this repository to your GitHub account
2. **Sign up** for a free account at [render.com](https://render.com)
3. **Create a new Web Service**:
   - Connect your GitHub repository
   - Choose the repository
   - Set the following:
     - **Name**: `cvss-server`
     - **Environment**: `Python`
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `python server.py`
4. **Deploy** - Render will automatically deploy your application

#### Environment Variables (Optional)
- `HOST`: `0.0.0.0` (default)
- `PORT`: `8000` (default)

### Option 2: Netlify (Frontend Only)

Since this is a Python server application, Netlify is not suitable for the backend. However, you could:

1. **Deploy the backend to Render** (as above)
2. **Create a simple frontend** that calls the Render API
3. **Deploy the frontend to Netlify**

### Option 3: Local Testing for Your Group

For testing with your group, you can:

1. **Run locally** and use a service like ngrok to expose your local server:
   ```bash
   # Install ngrok
   pip install pyngrok
   
   # Run your server
   python server.py
   
   # In another terminal, expose your local server
   ngrok http 8000
   ```

2. **Share the ngrok URL** with your group members

## API Endpoints

- `GET /` - Main evaluation form
- `GET /dashboard` - Dashboard with analytics
- `GET /api/dashboard/summary` - JSON summary of dashboard data
- `GET /api/vulns` - List all evaluations
- `GET /api/vulns/<id>` - Get specific evaluation
- `GET /api/export/csv` - Export all data as CSV
- `POST /evaluate` - Submit new evaluation

## CVSS Severity Levels

- **Critical** (9.0-10.0): Red gradient
- **High** (7.0-8.9): Orange gradient  
- **Medium** (4.0-6.9): Yellow gradient
- **Low** (0.1-3.9): Green gradient
- **None** (0.0): Gray gradient

## File Structure

```
cvss_server_project/
├── server.py          # Main server application
├── cvss.py           # CVSS calculation logic
├── database.db       # SQLite database (auto-created)
├── requirements.txt  # Python dependencies (empty - uses stdlib)
├── render.yaml       # Render deployment config
├── Procfile          # Render process file
├── runtime.txt       # Python version specification
└── README.md         # This file
```

## Technologies Used

- **Backend**: Python 3.9+ (Standard Library)
- **Database**: SQLite
- **Web Server**: http.server (built-in)
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Styling**: Modern CSS with gradients and animations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test locally
5. Submit a pull request

## License

This project is open source and available under the MIT License.
