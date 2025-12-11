-- Create the Cars table
CREATE TABLE IF NOT EXISTS cars (
    id SERIAL PRIMARY KEY,
    brand VARCHAR(100) NOT NULL,
    model VARCHAR(100) NOT NULL,
    year INT NOT NULL,
    mileage INT NOT NULL,
    price INT NOT NULL,
    description TEXT,
    image_url TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create the Admins table
CREATE TABLE IF NOT EXISTS admins (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS car_images (
    id SERIAL PRIMARY KEY,
    car_id INT REFERENCES cars(id) ON DELETE CASCADE,
    image_url TEXT NOT NULL
);

-- Insert a sample admin (Password is 'admin123')
-- The hash below is generated using bcrypt cost 10 for 'admin123'
INSERT INTO admins (username, password_hash) 
VALUES ('admin', '$2a$10$7/OceZq.vV8b4L5/Q5.dZOu.y.t.y/..hash..PLACEHOLDER');
-- Note: You should generate a real hash in Go code, but for quick testing, 
-- use the registration logic or an online bcrypt generator.