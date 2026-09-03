# Version 11 - Security & Credential Setup

The project now supports centralized environment-based configuration.

## Required environment variables

Set these before running the project:

- DB_HOST
- DB_PORT
- DB_NAME
- DB_USER
- DB_PASSWORD
- OTX_API_KEY
- ABUSEIPDB_API_KEY
- FLASK_SECRET_KEY
- FLASK_DEBUG

Use `.env.example` as the template. Do not put real credentials into `.env.example`.

## Windows PowerShell example

For the current terminal session:

    $env:DB_HOST="localhost"
    $env:DB_PORT="5432"
    $env:DB_NAME="ioc_database"
    $env:DB_USER="postgres"
    $env:DB_PASSWORD="YOUR_PASSWORD"
    $env:OTX_API_KEY="YOUR_OTX_KEY"
    $env:ABUSEIPDB_API_KEY="YOUR_ABUSEIPDB_KEY"
    $env:FLASK_SECRET_KEY="YOUR_RANDOM_SECRET"
    $env:FLASK_DEBUG="true"
    python app.py

## Important migration note

If older source files ever contained real API keys or database passwords, removing
them from the current files does not remove them from Git history or old ZIP files.
Rotate exposed API keys/passwords before publishing the repository.

## Production note

For a panel/demo environment, development mode is acceptable locally. For deployment,
set FLASK_DEBUG=false and use a proper WSGI server and secure secret management.
