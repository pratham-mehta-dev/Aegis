# Multi-stage Dockerfile for Aegis IDPS
# Stage 1: Build the React frontend SPA
FROM node:22-alpine AS frontend-builder
WORKDIR /app/frontend
COPY frontend/package*.json ./
RUN npm install
COPY frontend/ ./
RUN npm run build

# Stage 2: Production runtime image (Node.js + Python ML engine)
FROM node:22-alpine
WORKDIR /app

# Install Python 3 and pip for the ML microservice
RUN apk add --no-cache python3 py3-pip py3-gunicorn

# Install backend dependencies
COPY package*.json ./
RUN npm install --omit=dev

# Install Python ML dependencies
COPY ml_service/requirements.txt ./ml_service/
RUN python3 -m pip install --no-cache-dir --break-system-packages -r ml_service/requirements.txt

# Copy source code and built frontend bundle
COPY . .
COPY --from=frontend-builder /app/frontend/dist ./frontend/dist

# Expose unified port
EXPOSE 4001

# Start ML service on loopback and Aegis unified server
CMD python3 ml_service/app.py & node server.js
