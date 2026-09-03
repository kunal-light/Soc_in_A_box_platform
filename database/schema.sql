-- ===========================================
-- SOC-in-a-Box Database Schema
-- Log Collection Module
-- ===========================================

CREATE TABLE IF NOT EXISTS log_sources (

    id SERIAL PRIMARY KEY,

    source_name VARCHAR(100) NOT NULL,

    source_type VARCHAR(50) NOT NULL,

    hostname VARCHAR(100),

    ip_address VARCHAR(50),

    status VARCHAR(30) DEFAULT 'Active',

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);


CREATE TABLE IF NOT EXISTS raw_logs (

    id SERIAL PRIMARY KEY,

    source_id INTEGER REFERENCES log_sources(id),

    raw_message TEXT NOT NULL,

    received_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);


CREATE TABLE IF NOT EXISTS parsed_logs (

    id SERIAL PRIMARY KEY,

    raw_log_id INTEGER REFERENCES raw_logs(id),

    event_time TIMESTAMP,

    source_ip VARCHAR(50),

    destination_ip VARCHAR(50),

    username VARCHAR(100),

    hostname VARCHAR(100),

    event_type VARCHAR(100),

    severity VARCHAR(30),

    protocol VARCHAR(20),

    action VARCHAR(50),

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);


CREATE TABLE IF NOT EXISTS collectors (

    id SERIAL PRIMARY KEY,

    collector_name VARCHAR(100),

    collector_type VARCHAR(50),

    status VARCHAR(30),

    last_heartbeat TIMESTAMP,

    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

);