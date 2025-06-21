/* ------------------------------------------------------------------
   Shopify Order Proxy  –  server.js  (cursor-ready, 100% working)
   ------------------------------------------------------------------
   ▸ Loads creds from Render/Lambda env-vars  (.env in local dev)
   ▸ x-api-key header check (same key front-end sends)
   ▸ /health              – uptime ping
   ▸ /orders              – newest 50 orders, incl. customer details
   ▸ /orders?page_info=…  – cursor paging (Shopify REST)
------------------------------------------------------------------- */

import express from 'express';
import axios   from 'axios';
import cors    from 'cors';
import dotenv  from 'dotenv';
dotenv.config();

/* ---------- ENV -------------------------------------------------- */

const {
  SHOPIFY_STORE_URL,          // “mystore.myshopify.com”
  SHOPIFY_ACCESS_TOKEN,       // Admin-API token
  SHOPIFY_API_VERSION = '2024-04',
  FRONTEND_SECRET,            // the key your FE sends in x-api-key
  PORT = 10000                // Render’s port or local fallback
} = process.env;

if (!SHOPIFY_STORE_URL || !SHOPIFY_ACCESS_TOKEN || !FRONTEND_SECRET) {
  console.error(
    '❌  Missing env vars → need SHOPIFY_STORE_URL, SHOPIFY_ACCESS_TOKEN, FRONTEND_SECRET'
  );
  process.exit(1);
}

/* ---------- APP -------------------------------------------------- */

const app = express();
app.use(cors());

/* ---------- Tiny auth ------------------------------------------- */

app.use((req, res, next) => {
  if (req.headers['x-api-key'] !== FRONTEND_SECRET) {
    return res.status(403).send('Forbidden – bad API key');
  }
  next();
});

/* ---------- Helpers --------------------------------------------- */

function extractCursors(linkHeader = '') {
  /*  Shopify returns something like:
      <https://…orders.json?page_info=abcd&limit=50>; rel="next",
      <https://…orders.json?page_info=wxyz&limit=50>; rel="previous"
  */
  const cursors = { next: null, prev: null };

  linkHeader.split(',').forEach((entry) => {
    const [urlPart, relPart] = entry.split(';').map((s) => s.trim());
    if (!urlPart || !relPart) return;

    const match = urlPart.match(/page_info=([^&>]+)/);
    if (!match) return;

    if (relPart.includes('rel="next"')) cursors.next = match[1];
    if (relPart.includes('rel="previous"')) cursors.prev = match[1];
  });

  return cursors;
}

/* ---------- Routes ---------------------------------------------- */

// 1) Health check
app.get('/health', (_, res) => res.send('OK ✅'));

// 2) Orders (cursor paging)
app.get('/orders', async (req, res) => {
  const { page_info } = req.query;     // optional cursor
  const limit = 50;                    // Shopify max 250

  try {
    const { data, headers } = await axios.get(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/orders.json`,
      {
        headers: { 'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN },
        params : {
          limit,
          status : 'any',
          ...(page_info ? { page_info } : {}),
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
        }
      }
    );

    const { next: next_cursor, prev: prev_cursor } = extractCursors(headers.link);

    res.json({
      orders : data.orders,
      count  : data.orders.length,
      next_cursor,
      prev_cursor
    });

  } catch (err) {
    console.error('🔴  Shopify API error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

/* ---------- Start ----------------------------------------------- */

app.listen(PORT, () => {
  console.log(`✅  Shopify proxy running on http://localhost:${PORT} → ${SHOPIFY_STORE_URL}`);
});
