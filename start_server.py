#!/usr/bin/env python3
"""
Quick start script for the CVSS Server.
This script provides a nice startup experience with clear instructions.
"""

import os
import sys
import webbrowser
import time
from pathlib import Path

def print_banner():
    """Print a nice banner for the CVSS server."""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    CVSS v3.1 Scoring System                  ║
    ║                                                              ║
    ║  🚀 Starting server...                                       ║
    ║  📊 Dashboard will be available at: http://localhost:8000   ║
    ║  📝 API endpoints available at: /api/*                      ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_dependencies():
    """Check if all required files are present."""
    required_files = ['server.py', 'cvss.py']
    missing_files = []
    
    for file in required_files:
        if not Path(file).exists():
            missing_files.append(file)
    
    if missing_files:
        print(f"❌ Missing required files: {', '.join(missing_files)}")
        return False
    
    print("✓ All required files found")
    return True

def open_browser():
    """Open the browser to the CVSS server."""
    try:
        # Wait a moment for the server to start
        time.sleep(2)
        webbrowser.open('http://localhost:8000')
        print("🌐 Opening browser...")
    except Exception as e:
        print(f"⚠️  Could not open browser automatically: {e}")
        print("   Please open http://localhost:8000 manually")

def main():
    """Main function to start the CVSS server."""
    print_banner()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    print("\n📋 Server Information:")
    print("   • Main page: http://localhost:8000")
    print("   • Dashboard: http://localhost:8000/dashboard")
    print("   • API Summary: http://localhost:8000/api/dashboard/summary")
    print("   • Export CSV: http://localhost:8000/api/export/csv")
    
    print("\n💡 Tips:")
    print("   • Press Ctrl+C to stop the server")
    print("   • Use ngrok_setup.py to share with your team")
    print("   • Check README.md for deployment options")
    
    print("\n" + "="*60)
    
    # Import and run the server
    try:
        from server import run_server
        open_browser()
        run_server()
    except KeyboardInterrupt:
        print("\n🛑 Server stopped by user")
    except Exception as e:
        print(f"\n❌ Error starting server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
