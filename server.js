/**
 * server.js  – Shopify Admin Proxy
 *
 * • Secured with x-api-key (FRONTEND_SECRET env var)
 * • /health           → simple uptime check (public)
 * • /orders           → returns ALL orders (250 per page) from Jan 2023 onward
 *
 * Required Render env vars:
 *   SHOPIFY_SHOP           = exposurepack.myshopify.com
 *   SHOPIFY_ACCESS_TOKEN   = shpat_********************************
 *   FRONTEND_SECRET        = mypassword123        (matches Shopify theme JS)
 */

const express = require('express');
const axios   = require('axios');
const cors    = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());

// ──────────────────────────────────────────────────────────
// Public health-check route (no API key required)
app.get('/health', (_req, res) => {
  res.send('OK');
});

// API-key middleware  (everything below here is protected)
app.use((req, res, next) => {
  if (req.headers['x-api-key'] !== process.env.FRONTEND_SECRET) {
    return res.status(403).send('Forbidden – bad API key');
  }
  next();
});

// ──────────────────────────────────────────────────────────
// /orders – fetch all orders (beyond 60-day limit)
//
// NOTE:   Returns the first 250 results.  Add pagination later if needed.
//
app.get('/orders', async (req, res) => {
  try {
    const { data } = await axios.get(
      `https://${process.env.SHOPIFY_SHOP}/admin/api/2024-04/orders.json`,
      {
        headers: { 'X-Shopify-Access-Token': process.env.SHOPIFY_ACCESS_TOKEN },
        params : {
          limit          : 250,                       // Shopify max
          status         : 'any',                     // all orders
          created_at_min : '2023-01-01T00:00:00Z'     // change if needed
        }
      }
    );

    res.json({
      orders       : data.orders,
      current_page : 1,
      total_pages  : 1,             // update if you add pagination
      total_count  : data.orders.length
    });
  } catch (err) {
    console.error('Shopify API error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// ──────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Proxy server running on port ${PORT}`);
});
