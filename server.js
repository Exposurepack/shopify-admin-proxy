/* ------------------------------------------------------------------
   Shopify Order Proxy  –  server.js  (fixed)
   ------------------------------------------------------------------
   ▸ Loads credentials from Render env-vars (.env in local dev)
   ▸ Simple x-api-key header check (same key the front-end sends)
   ▸ /health              – uptime ping
   ▸ /orders              – latest 50 orders incl. customer details
   ▸ /orders?page_info=…  – follow Shopify cursor for next 50
------------------------------------------------------------------- */

import express from 'express';
import axios   from 'axios';
import cors    from 'cors';
import dotenv  from 'dotenv';
dotenv.config();

/* ----- Environment ------------------------------------------------ */

const {
  SHOPIFY_STORE_URL,      // mystore.myshopify.com
  SHOPIFY_ACCESS_TOKEN,   // Admin-API token
  SHOPIFY_API_VERSION = '2024-04',
  FRONTEND_SECRET,        // Password your front-end sends in x-api-key
  PORT = 10000            // Render (or local) port
} = process.env;

if (!SHOPIFY_STORE_URL || !SHOPIFY_ACCESS_TOKEN || !FRONTEND_SECRET) {
  console.error('❌  Missing env vars.  Set SHOPIFY_STORE_URL, SHOPIFY_ACCESS_TOKEN, FRONTEND_SECRET.');
  process.exit(1);
}

/* ----- App boilerplate ------------------------------------------- */

const app = express();
app.use(cors());

/* ----- Tiny auth middleware -------------------------------------- */

app.use((req, res, next) => {
  if (req.headers['x-api-key'] !== FRONTEND_SECRET) {
    return res.status(403).send('Forbidden – bad API key');
  }
  next();
});

/* ----- Routes ----------------------------------------------------- */

// 1) Health-check ─ used by Render & you
app.get('/health', (_, res) => res.send('OK ✅'));

// 2) Orders – cursor-based pagination (Shopify REST)
app.get('/orders', async (req, res) => {
  const limit      = 50;                       // up to 250
  const { page_info } = req.query;             // optional cursor

  try {
    /* ---------- Build request ----------------------------------- */

    const url = `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/orders.json`;
    const params = {
      limit,
      status : 'any',                          // open, closed, cancelled, fulfilled…
      fields : [
        'id',
        'name',
        'created_at',
        'financial_status',
        'fulfillment_status',
        'total_price',
        'currency',
        'customer',
        'billing_address',
        'shipping_address'
      ].join(',')
    };
    if (page_info) params.page_info = page_info;   // cursor for next/prev page

    /* ---------- Call Shopify ------------------------------------ */

    const { data, headers } = await axios.get(url, {
      headers : { 'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN },
      params
    });

    /* ---------- Parse pagination cursors ------------------------ */

    let next_cursor = null;
    let prev_cursor = null;
    if (headers.link) {
      // Example: <https://…page_info=abcd>; rel="next", <https://…page_info=wxyz>; rel="previous"
      headers.link.split(',').forEach(entry => {
        const [link, rel] = entry.split(';');
        const cursor      = new URL(link.replace(/[<> ]/g, '')).searchParams.get('page_info');
        if (rel.includes('rel="next"'))     next_cursor = cursor;
        if (rel.includes('rel="previous"')) prev_cursor = cursor;
      });
    }

    /* ---------- Respond ---------------------------------------- */

    res.json({
      orders      : data.orders,
      count       : data.orders.length,
      next_cursor,
      prev_cursor
    });

  } catch (err) {
    console.error('🔴  Shopify API error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

/* ----- Start server ---------------------------------------------- */

app.listen(PORT, () => {
  console.log(`✅  Shopify proxy running on http://localhost:${PORT}  →  ${SHOPIFY_STORE_URL}`);
});
