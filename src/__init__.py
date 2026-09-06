"""
SecureNet Lab — Self-hosted network security monitoring system.

Modules:
    config      — Centralized configuration management
    models      — Core data models (Event, IP, Ban, etc.)
    database    — SQLite persistence layer
    logger      — Structured JSON logging
    api         — REST API for dashboard consumption
    orchestrator — Main pipeline entry point
    collector   — Log collection from remote servers
    detector    — Attack detection engine
    threat_intel — IP reputation lookups (AbuseIPDB)
    auto_ban    — Firewall auto-ban automation
    alerts      — Notification system (Telegram, email)
"""
