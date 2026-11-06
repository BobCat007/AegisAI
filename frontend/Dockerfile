FROM node:20-alpine AS build

WORKDIR /app

COPY frontend/package*.json ./
RUN if [ -f package-lock.json ]; then npm ci; else npm install; fi

COPY frontend/ ./
RUN npm run build

FROM nginx:1.27-alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY deployment/nginx/default.conf.template \
     /etc/nginx/templates/default.conf.template

EXPOSE 80
