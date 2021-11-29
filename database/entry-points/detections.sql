CREATE TABLE detections (
    detection_id SERIAL PRIMARY KEY,
    detection_time TIMESTAMP NOT NULL,
    attacker_ip_address VARCHAR(15) NOT NULL,
    module_name VARCHAR(20) NOT NULL,
    note VARCHAR(255)
)