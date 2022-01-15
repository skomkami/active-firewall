CREATE TABLE detections (
    detection_id SERIAL PRIMARY KEY,
    detection_time TIMESTAMP NOT NULL,
    attacker_ip_address VARCHAR(15) NOT NULL,
    module_name VARCHAR(30) NOT NULL,
    note VARCHAR(255)
);

CREATE TABLE dos_module_stats (
    id SERIAL PRIMARY KEY,
    time_window_start TIMESTAMP NOT NULL,
    time_window_end TIMESTAMP NOT NULL,
    mean_packets_per_addr REAL,
    mean_packets_size_per_addr REAL
);

CREATE TABLE brute_force_module_stats (
    id SERIAL PRIMARY KEY,
    time_window_start TIMESTAMP NOT NULL,
    time_window_end TIMESTAMP NOT NULL,
    mean_attempts_per_addr REAL
);

CREATE TABLE port_scanning_module_stats (
    id SERIAL PRIMARY KEY,
    time_window_start TIMESTAMP NOT NULL,
    time_window_end TIMESTAMP NOT NULL,
    mean_scans_per_addr REAL
);