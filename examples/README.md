# PyAuth Examples

## FastAPI + SQLAlchemy (Post-Phase 3)

A minimal FastAPI app wired to PyAuth with SQLAlchemy and SQLite.

### Run

```bash
# From project root
uv sync --extra fastapi --extra sqlalchemy
uv run uvicorn examples.fastapi_sqlalchemy_app:app --reload
```

Open http://localhost:8000/docs for the interactive API.

### Try it

**Sign up**
```bash
curl -X POST http://localhost:8000/api/auth/sign-up \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"SecurePass123"}' \
  -c cookies.txt -b cookies.txt
```

**Sign in**
```bash
curl -X POST http://localhost:8000/api/auth/sign-in \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"SecurePass123"}' \
  -c cookies.txt -b cookies.txt
```

**Protected route**
```bash
curl http://localhost:8000/me -b cookies.txt
```

**Sign out**
```bash
curl -X POST http://localhost:8000/api/auth/sign-out -b cookies.txt -c cookies.txt
```

### OAuth (Google / GitHub)

Replace the placeholder `client_id` and `client_secret` in `fastapi_sqlalchemy_app.py` with real credentials from your provider's developer console. Then visit:

- http://localhost:8000/api/auth/oauth/google
- http://localhost:8000/api/auth/oauth/github

### Database

The sample uses SQLite (`pyauth_sample.db` in the current directory). For PostgreSQL:

```python
engine = create_async_engine("postgresql+asyncpg://user:pass@localhost/dbname")
```
