-- Table 1: Authentication
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'analyst',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table 2: The Core SOC Data
CREATE TABLE IF NOT EXISTS zscaler_logs (
    id SERIAL PRIMARY KEY,
    log_time TIMESTAMP NOT NULL,
    user_login VARCHAR(255),
    department VARCHAR(255),
    device_name VARCHAR(255),
    source_ip INET,
    dest_ip INET,
    url TEXT,
    bytes_sent BIGINT DEFAULT 0,
    bytes_received BIGINT DEFAULT 0,
    action VARCHAR(50),
    threat_name VARCHAR(255),
    risk_score INTEGER,
    
    -- Bonus: AI & ML Detection
    is_anomaly BOOLEAN DEFAULT FALSE,
    confidence_score FLOAT,
    ai_explanation TEXT,
    
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for faster frontend loading
CREATE INDEX IF NOT EXISTS idx_user_time ON zscaler_logs(user_login, log_time);