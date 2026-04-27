FROM node:24-alpine AS build

WORKDIR /app

ARG VITE_API_BASE_URL=http://127.0.0.1:5000
ARG VITE_HIDE_DEV_TOKEN_ENTRY=false
ENV VITE_API_BASE_URL=$VITE_API_BASE_URL
ENV VITE_HIDE_DEV_TOKEN_ENTRY=$VITE_HIDE_DEV_TOKEN_ENTRY

COPY analyst-web/package.json ./
RUN npm install

COPY analyst-web .
RUN npm run build

FROM nginx:1.27-alpine

COPY --from=build /app/dist /usr/share/nginx/html
COPY analyst-web/nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
