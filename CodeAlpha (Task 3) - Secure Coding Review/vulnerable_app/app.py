"""INTENTIONALLY INSECURE: local educational lab only. Never deploy."""
import sqlite3
from flask import Flask, request, render_template_string

app = Flask(__name__)
app.config['SECRET_KEY'] = 'demo-hardcoded-secret'  # V-03
DB = ':memory:'

@app.get('/')
def home():
    name = request.args.get('name', 'visitor')
    # V-02: user input directly interpolated into HTML
    return render_template_string('<h1>Hello ' + name + '</h1>')

@app.get('/lookup')
def lookup():
    username = request.args.get('username', '')
    connection = sqlite3.connect(DB)
    connection.execute('CREATE TABLE users (username TEXT)')
    connection.execute("INSERT INTO users VALUES ('demo')")
    # V-01: concatenated SQL (unsafe)
    query = "SELECT username FROM users WHERE username = '" + username + "'"
    try:
        rows = connection.execute(query).fetchall()
        return {'users': [row[0] for row in rows]}
    except sqlite3.Error:
        return {'error': 'Invalid query'}, 400
    finally:
        connection.close()

if __name__ == '__main__':
    # V-04: debug server should not be used for production
    app.run(host='127.0.0.1', port=5001, debug=True)
