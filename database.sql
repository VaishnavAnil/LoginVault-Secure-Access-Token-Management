CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    failed_attempts INT DEFAULT 0,
    locked BOOLEAN DEFAULT false
);

CREATE TABLE one_time_links (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) REFERENCES users(username),
    token TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL
);
