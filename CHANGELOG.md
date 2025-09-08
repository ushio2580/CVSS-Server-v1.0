# Changelog

All notable changes to the CVSS Server v1.0 project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-09-07

### Added
- **Complete Authentication System**
  - User registration and login functionality
  - Secure password hashing with SHA256 + salt
  - Session management with HttpOnly cookies
  - User logout and session cleanup
  - User profile information display

- **Advanced Document Processing**
  - Word (.docx) document analysis
  - PDF document text extraction
  - Automatic CVSS metric detection from documents
  - Smart form pre-filling with detected values
  - Pattern recognition for vulnerability descriptions

- **Collaborative Dashboard**
  - Global view of all team evaluations
  - Personal filtering for individual user evaluations
  - Dynamic filtering with URL parameters
  - User attribution for each evaluation
  - Real-time analytics and charts

- **Enhanced User Interface**
  - Modern responsive design
  - Gradient-based severity color coding
  - Interactive filter buttons
  - Smooth animations and transitions
  - Mobile-friendly layout

- **Comprehensive API**
  - RESTful endpoints for all functionality
  - JSON responses for programmatic access
  - CSV export functionality
  - Authentication-protected routes

### Changed
- **Database Schema**
  - Added users table for authentication
  - Added user_sessions table for session management
  - Added user_id foreign key to evaluations table
  - Enhanced queries with JOIN operations

- **Security Improvements**
  - All routes now require authentication
  - Secure cookie handling
  - SQL injection protection
  - Input validation and sanitization

- **Performance Optimizations**
  - Efficient database queries
  - Optimized document processing
  - Improved error handling
  - Better memory management

### Technical Details
- **Backend**: Python 3.12 with standard library
- **Database**: SQLite with enhanced schema
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Deployment**: Railway cloud platform
- **Dependencies**: Minimal external packages

### Security
- Password hashing with SHA256 + unique salt
- HttpOnly cookies for session management
- Parameterized SQL queries
- Input validation and sanitization
- CSRF protection through session tokens

## [0.9.0] - 2024-08-30

### Added
- Basic CVSS v3.1 calculation engine
- Simple web interface
- SQLite database integration
- Basic dashboard with charts
- API endpoints for data access

### Changed
- Initial project structure
- Basic deployment configuration

## [0.8.0] - 2024-08-28

### Added
- Initial CVSS calculation logic
- Basic web server implementation
- Core database functionality
- Project foundation

---

## Migration Guide

### From v0.9.0 to v1.0.0

1. **Database Migration**: The database schema has been updated. Existing databases will need to be recreated or migrated.

2. **Authentication**: All routes now require authentication. Users must register and login to access the application.

3. **New Features**: Document processing and collaborative features are now available.

4. **API Changes**: Some API endpoints now require authentication headers.

### Breaking Changes

- **Authentication Required**: All routes now require user authentication
- **Database Schema**: New tables added (users, user_sessions)
- **API Authentication**: API endpoints now require valid session cookies

---

## Support

For questions about migration or any issues, please:
- Open an issue on [GitHub](https://github.com/ushio2580/CVSS-Server-v1.0/issues)
- Check the [documentation](https://github.com/ushio2580/CVSS-Server-v1.0#readme)
- Contact through GitHub profile
