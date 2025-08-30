#!/usr/bin/env python3
"""
Helper script to expose the local CVSS server using ngrok for group testing.
This allows your team members to access your local server from anywhere.

Usage:
    python ngrok_setup.py

Requirements:
    pip install pyngrok
"""

import subprocess
import sys
import time
from pyngrok import ngrok

def install_ngrok():
    """Install ngrok if not already installed."""
    try:
        import pyngrok
        print("✓ pyngrok already installed")
    except ImportError:
        print("Installing pyngrok...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "pyngrok"])
        print("✓ pyngrok installed successfully")

def start_ngrok_tunnel(port=8000):
    """Start ngrok tunnel to expose local server."""
    try:
        # Start the tunnel
        public_url = ngrok.connect(port)
        print(f"\n🚀 CVSS Server is now accessible at:")
        print(f"   {public_url}")
        print(f"\n📊 Dashboard: {public_url}/dashboard")
        print(f"📝 API: {public_url}/api/dashboard/summary")
        print(f"\n💡 Share this URL with your team members!")
        print(f"\n⏹️  Press Ctrl+C to stop the tunnel")
        
        # Keep the tunnel open
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n🛑 Stopping ngrok tunnel...")
            ngrok.kill()
            print("✓ Tunnel stopped")
            
    except Exception as e:
        print(f"❌ Error starting ngrok: {e}")
        print("Make sure you have an internet connection and ngrok is properly installed.")

def main():
    print("🔧 Setting up ngrok tunnel for CVSS Server...")
    
    # Install pyngrok if needed
    install_ngrok()
    
    # Check if server is running
    print("\n⚠️  Make sure your CVSS server is running first!")
    print("   Run: python server.py")
    print("   Then run this script in another terminal.\n")
    
    input("Press Enter when your server is running...")
    
    # Start the tunnel
    start_ngrok_tunnel()

if __name__ == "__main__":
    main()
