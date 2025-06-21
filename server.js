/* ------------------------------------------------------------------
   Shopify Order Proxy  –  server.js  (cursor paging  +  metafields)
   ------------------------------------------------------------------
   ▸ Reads env-vars (Render / fly.io / Heroku) – .env in local dev
   ▸ x-api-key middleware
   ▸ /health                 → uptime ping
   ▸ /orders                 → newest 50 orders + custom metafields
   ▸ /orders?page_info=…     → follow Shopify cursor (REST)
------------------------------------------------------------------- */

import express from 'express';
import axios   from 'axios';
import cors    from 'cors';
import dotenv  from 'dotenv';
dotenv.config();

/* ---------- ENV -------------------------------------------------- */

const {
  SHOPIFY_STORE_URL,          // mystore.myshopify.com
  SHOPIFY_ACCESS_TOKEN,       // Admin-API token
  SHOPIFY_API_VERSION = '2024-04',
  FRONTEND_SECRET,            // FE sends this in x-api-key
  PORT = 10000
} = process.env;

if (!SHOPIFY_STORE_URL || !SHOPIFY_ACCESS_TOKEN || !FRONTEND_SECRET) {
  console.error(
    '❌  Missing env vars – need SHOPIFY_STORE_URL, SHOPIFY_ACCESS_TOKEN, FRONTEND_SECRET'
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
  const cursors = { next: null, prev: null };
  linkHeader.split(',').forEach(entry => {
    const [urlPart, relPart] = entry.split(';').map(s => s.trim());
    if (!urlPart || !relPart) return;
    const match = urlPart.match(/page_info=([^&>]+)/);
    if (!match) return;
    if (relPart.includes('rel="next"'))     cursors.next = match[1];
    if (relPart.includes('rel="previous"')) cursors.prev = match[1];
  });
  return cursors;
}

/* ---------- Routes ---------------------------------------------- */

// 1) Health check
app.get('/health', (_, res) => res.send('OK ✅'));

// 2) Orders (cursor paging + metafields)
app.get('/orders', async (req, res) => {
  const { page_info } = req.query;   // optional cursor
  const limit = 50;                  // Shopify max 250

  try {
    /* -------- 1. Grab the order list --------------------------- */

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

    /* -------- 2. Fetch metafields for each order --------------- */

    const ordersWithMeta = await Promise.all(
      data.orders.map(async (order) => {
        try {
          const mfRes = await axios.get(
            `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/orders/${order.id}/metafields.json`,
            {
              headers: { 'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN },
              params : { namespace: 'custom', limit: 250 }   // adjust if you use a different namespace
            }
          );

          // Reduce the array into a simple { key: value } object
          const customMetafields = {};
          mfRes.data.metafields.forEach(mf => {
            customMetafields[mf.key] = mf.value;
          });

          return { ...order, customMetafields };

        } catch (mfErr) {
          console.error(`⚠️  Could not load metafields for order ${order.name}`, mfErr.message);
          return { ...order, customMetafields: {} };
        }
      })
    );

    /* -------- 3. Pagination cursors ---------------------------- */

    const { next: next_cursor, prev: prev_cursor } = extractCursors(headers.link);

    /* -------- 4. Respond --------------------------------------- */

    res.json({
      orders: ordersWithMeta,
      count : ordersWithMeta.length,
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
  console.log(`✅  Shopify proxy running on http://localhost:${PORT}  →  ${SHOPIFY_STORE_URL}`);
});
