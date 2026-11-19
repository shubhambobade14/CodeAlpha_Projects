from secure_app.app import create_app


def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_html_escaping():
    response = client().get('/', query_string={'name': '<script>alert(1)</script>'})
    body = response.get_data(as_text=True)
    assert '<script>' not in body
    assert '&lt;script&gt;' in body


def test_lookup_parameterization():
    response = client().get('/lookup', query_string={'username': "' OR 1=1 --"})
    assert response.status_code == 200
    assert response.json == {'users': []}


def test_valid_lookup():
    assert client().get('/lookup', query_string={'username': 'demo'}).json == {'users': ['demo']}


def test_invalid_lookup():
    assert client().get('/lookup').status_code == 400


def test_security_headers():
    response = client().get('/')
    assert response.headers['X-Content-Type-Options'] == 'nosniff'
    assert 'Content-Security-Policy' in response.headers


def test_debug_disabled():
    assert create_app().debug is False
