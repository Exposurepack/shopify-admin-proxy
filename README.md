# Shopify Admin Proxy

A lightweight Express server that fetches Shopify order data securely.

## Environment Variables (.env)

- `SHOPIFY_STORE_URL`: Your Shopify store domain (e.g. exposurepack.myshopify.com)
- `SHOPIFY_ACCESS_TOKEN`: Admin API token from your private app
- `SHOPIFY_API_VERSION`: e.g. 2024-04
- `FRONTEND_SECRET`: Secret key used to allow frontend access
- `PORT`: The port this app will run on (Render uses 10000 by default)

## Endpoints

- `GET /orders`: Returns paginated Shopify orders
- `GET /health`: Health check
