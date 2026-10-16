# Recette utilisée par Render pour construire et lancer l'application.
# Tu n'as rien à modifier ici : Render la lit automatiquement.

# Étape 1 — construire le frontend React (Node)
FROM node:20-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Étape 2 — le backend Python qui sert le frontend construit
FROM python:3.12-slim
WORKDIR /app
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt
COPY backend/ ./backend/
COPY --from=frontend /app/frontend/dist ./frontend/dist
WORKDIR /app/backend
# Render fournit le port via la variable $PORT.
CMD uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}
