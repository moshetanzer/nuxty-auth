CREATE TABLE users (
    id VARCHAR(250) PRIMARY KEY,
    fname VARCHAR(50) NOT NULL,
    lname VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR NOT NULL,
    role VARCHAR(20) NOT NULL,
    failed_attempts INTEGER DEFAULT 0 NOT NULL,
    email_verified BOOLEAN DEFAULT false NOT NULL,
    mfa BOOLEAN DEFAULT false NOT NULL,
    reset_token VARCHAR(100),
    reset_token_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

CREATE INDEX idx_users_id ON users(id);

CREATE INDEX idx_users_email ON users (email);

CREATE INDEX idx_users_role ON users (role);

CREATE TABLE mfa (
    id SERIAL PRIMARY KEY,
    type VARCHAR(20) NOT NULL DEFAULT 'email',
    user_id VARCHAR(255) NOT NULL,
    secret VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

CREATE INDEX idx_mfa_user_id ON mfa (user_id);

ALTER TABLE ONLY mfa
    ADD CONSTRAINT mfa_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

CREATE TABLE email_verification (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(15) NOT NULL,
    token VARCHAR(100) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);

CREATE INDEX idx_email_verification_user_id ON email_verification (user_id);

ALTER TABLE ONLY email_verification
    ADD CONSTRAINT email_verification_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
    
CREATE TABLE sessions (
    id UUID PRIMARY KEY,
    user_id VARCHAR(255),
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now(),
    last_activity_at TIMESTAMPTZ DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    mfa_verified BOOLEAN DEFAULT false NOT NULL
);

CREATE INDEX idx_sessions_expires_at ON sessions (expires_at);

CREATE INDEX idx_sessions_user_id ON sessions (user_id);

ALTER TABLE ONLY sessions
    ADD CONSTRAINT sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

CREATE TABLE audit_logs (
    id SERIAL PRIMARY KEY,
    email VARCHAR(100) NOT NULL,
    action VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    ip VARCHAR(50),
    user_agent TEXT,
    status VARCHAR(20) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT now() NOT NULL
);