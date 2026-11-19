"""Remediated Flask demo. No external deployment configuration included."""
import os
import sqlite3
from flask import Flask, request, render_template, jsonify


def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY') or os.urandom(32)

    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Referrer-Policy'] = 'no-referrer'
        response.headers['Content-Security-Policy'] = "default-src 'self'; object-src 'none'; base-uri 'self'"
        return response

    @app.get('/')
    def home():
        name = request.args.get('name', 'visitor')[:80]
        # Jinja HTML autoescaping in .html template
        return render_template('index.html', name=name)

    @app.get('/lookup')
    def lookup():
        username = request.args.get('username', '')
        if not username or len(username) > 80:
            return jsonify(error='username must be 1-80 characters'), 400
        with sqlite3.connect(':memory:') as connection:
            connection.execute('CREATE TABLE users (username TEXT)')
            connection.execute('INSERT INTO users VALUES (?)', ('demo',))
            rows = connection.execute('SELECT username FROM users WHERE username = ?', (username,)).fetchall()
        return jsonify(users=[row[0] for row in rows])

    return app

app = create_app()
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5002, debug=False)
