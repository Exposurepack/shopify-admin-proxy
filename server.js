/* ------------------------------------------------------------------
   Shopify Order Proxy - server.js
   ------------------------------------------------------------------
   ▸ Loads credentials from Render env-vars (.env in local dev)
   ▸ Simple x-api-key header check (same key front-end sends)
   ▸ /health            – uptime ping
   ▸ /orders?page=1     – returns latest orders (incl. customer info)
------------------------------------------------------------------- */

import express from 'express';
import axios   from 'axios';
import cors    from 'cors';
import dotenv  from 'dotenv';
dotenv.config();

/* ----- Environment ------------------------------------------------ */

const {
  SHOPIFY_STORE_URL,      // mystore.myshopify.com
  SHOPIFY_ACCESS_TOKEN,   // Admin API token
  SHOPIFY_API_VERSION = '2024-04',
  FRONTEND_SECRET,        // Password your front-end sends in x-api-key
  PORT = 10000            // Render listens on whatever you expose
} = process.env;

if (!SHOPIFY_STORE_URL || !SHOPIFY_ACCESS_TOKEN || !FRONTEND_SECRET) {
  console.error('❌  Missing env vars.  Please set SHOPIFY_STORE_URL, SHOPIFY_ACCESS_TOKEN, and FRONTEND_SECRET.');
  process.exit(1);
}

/* ----- App boilerplate ------------------------------------------- */

const app = express();
app.use(cors());

/* ----- Tiny auth middleware -------------------------------------- */

app.use((req, res, next) => {
  const key = req.headers['x-api-key'];
  if (key !== FRONTEND_SECRET) return res.status(403).send('Forbidden – bad API key');
  next();
});

/* ----- Routes ----------------------------------------------------- */

// 1) Health-check ─ used by Render & you
app.get('/health', (_, res) => res.send('OK ✅'));

// 2) Orders – add `?page=` if you want basic paging
app.get('/orders', async (req, res) => {
  const page  = Number(req.query.page || 1);
  const limit = 50;                       // Shopify max = 250

  try {
    const { data } = await axios.get(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/orders.json`,
      {
        headers: { 'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN },
        params : {
          status : 'any',                 // open, closed, cancelled, fulfilled, etc.
          limit,
          page,
          /*  ---- fields ----
              Leaving fields **blank** returns the full order object, which
              includes:
                – customer.first_name / last_name / email
                – billing_address / shipping_address
                – line_items, tags, notes, etc.
              If you’d rather slim the payload, list the fields you need, e.g.:
              fields: 'id,name,total_price,created_at,currency,customer,billing_address,shipping_address'
          */
        }
      }
    );

    res.json({
      orders       : data.orders,
      current_page : page,
      total_pages  : 1,          // ─────► change if you add real pagination
      total_count  : data.orders.length
    });

  } catch (err) {
    console.error('🔴  Shopify API error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

/* ----- Start server ---------------------------------------------- */

app.listen(PORT, () => {
  console.log(`✅  Shopify proxy running on http://localhost:${PORT} → ${SHOPIFY_STORE_URL}`);
});
