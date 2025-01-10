import sqlite3

def create_connection():
    conn = sqlite3.connect('users.db')
    return conn

def create_table():
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def insert_user(email, password):
    conn = create_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO users (email, password) VALUES (?, ?)', (email, password))
    conn.commit()
    conn.close()

# Create the table and insert a test user
create_table()
insert_user('jay.ramwani1983@gmail.com', 'password123')  # Replace with a hashed password in a real app