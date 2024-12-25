
# Access Control System for Small Organizations

vanyca = manager

## Overview

This Flask-based web application is designed to implement a user authentication and role-based access control (RBAC) system for small organizations. It allows users to register, log in, and manage their profiles, while administrators can manage user accounts, view the user list, and delete users.

## Features

- **User Registration and Login**: Allows users to register and log in with their credentials.
- **Role-based Access Control (RBAC)**: Differentiates between 'user' and 'admin' roles with specific permissions.
- **User Profile Management**: Users can view and edit their profiles, including personal information and password changes.
- **Admin Dashboard**: Admins can view, create, and delete user accounts, as well as manage user-related activities.
- **Activity Tracking**: Users can track and log different activities like walking, running, and meditation, along with specific counters for each activity type.
- **Secure Authentication**: Passwords are hashed for secure storage and validation.

## Requirements

- Python 3.x
- Flask
- Flask-MySQLdb
- Werkzeug
- MySQL Database

## Setup Instructions

1. **Clone the Repository**:

   ```bash
   git clone <repository-url>
   cd <repository-directory>
   ```

2. **Install Dependencies**:
   Install the required Python packages using `pip`:

   ```bash
   pip install -r requirements.txt
   ```

3. **Setup the MySQL Database**:
   Create a MySQL database and configure the `app.config` variables in `app.py` with your database credentials:

   ```python
   app.config['MYSQL_HOST'] = 'localhost'
   app.config['MYSQL_USER'] = 'root'
   app.config['MYSQL_PASSWORD'] = ''
   app.config['MYSQL_DB'] = 'wellness_program'
   ```

   Execute the required SQL commands to create the necessary tables for users and activities. Use the following SQL script:

   ```sql
   CREATE TABLE users (
       id INT AUTO_INCREMENT PRIMARY KEY,
       username VARCHAR(50) NOT NULL UNIQUE,
       first_name VARCHAR(50),
       last_name VARCHAR(50),
       birthdate DATE,
       address TEXT,
       contact_number VARCHAR(15),
       email VARCHAR(100) NOT NULL UNIQUE,
       password VARCHAR(255) NOT NULL,
       role ENUM('admin', 'user') NOT NULL,
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
   );

   CREATE TABLE activities (
       id INT AUTO_INCREMENT PRIMARY KEY,
       activity_name VARCHAR(100),
       activity_type ENUM('walking', 'running', 'cycling', 'meditation'),
       description TEXT,
       date DATE,
       time TIME,
       username VARCHAR(50),
       counter_type VARCHAR(50),
       counter_description TEXT,
       FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
   );
   ```

4. **Run the Application**:
   Start the Flask application by running:

   ```bash
   python app.py
   ```

5. Open a browser and navigate to `http://127.0.0.1:5000/` to access the app.

## Usage

- **User Flow**:

  1. Register an account with required details.
  2. Log in to your account.
  3. View or edit your profile.
  4. Track your activities (e.g., walking, running, meditation).
  5. Logout when done.

- **Admin Flow**:

  1. Log in with admin credentials.
  2. View the admin dashboard to manage users.
  3. Create new users or delete existing ones.
  4. Logout when done.

## Security Features

- **Password Hashing**: Passwords are hashed using `werkzeug.security` to ensure secure storage.
- **Session Management**: User sessions are securely handled using Flask's session management, with role-based redirection.
- **Input Validation**: User inputs (e.g., username, email) are validated using regular expressions to prevent invalid data entry.
- **Role-Based Access Control (RBAC)**: Users are assigned roles, and access to specific pages or functionalities is restricted based on roles (e.g., admin or user).

## License

This project is licensed under the MIT License.
