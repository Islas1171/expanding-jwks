# expanding-jwks
This project implements a JWKS server that:
Encrypts private keys in the database using AES.
Supports user registration.
Provides user authentication with Argon2.
Logs authentication attempts in an auth_logs table.
Implements rate-limiting for /auth requests.

AES Encryption: Encrypts private keys stored in the database for security.
Creates users with a randomly generated secure password.
Verifies user credentials and logs login attempts.
Limits excessive /auth requests (10 requests per second).
SQLite for persistent storage of users, keys, and logs.

# Prerequisites
Python 3.10+
pip for installing dependencies
# Project Setup
Step 1: Clone the Repository
cd jwks-server
Step 2: Create a Virtual Environment
python -m venv .venv
.venv\Scripts\activate
Step 3: Set Up Environment Variables
Define the environment variable NOT_MY_KEY for AES encryption:

set NOT_MY_KEY=Super_SecretKey     
Step 5: Initialize the Database
Run the server script to initialize the database tables:

python project3.py

The script will create the following tables in totally_not_my_privateKeys.db:
users: Stores user details and hashed passwords.
auth_logs: Logs authentication attempts.
keys: Stores encrypted private keys.
Running the Server
Start the server:

python project3.py
The server runs at http://localhost:8080 by default.

# Common Errors
ValueError: Environment variable NOT_MY_KEY is not set.

Ensure NOT_MY_KEY is set in your environment before running the server.
SQL logic error: no such table

Ensure the database is initialized by running python project3.py.
![image](https://github.com/user-attachments/assets/cc1e60cc-f15a-4e1f-ab84-5e5354fe9d28)

![image](https://github.com/user-attachments/assets/4fa203e7-f9c0-4c82-b0a8-ff3270c612a5)

![image](https://github.com/user-attachments/assets/890dea6a-b534-49a7-8975-dc9280e87772)
