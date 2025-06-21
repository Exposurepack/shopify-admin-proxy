/* ------------------------------------------------------------------
   Shopify Order Proxy  –  server.js (GraphQL version)
   ------------------------------------------------------------------
   ▸ Loads creds from .env / Render Service Vars
   ▸ Secure x-api-key check
   ▸ /health          – for uptime pings
   ▸ /orders          – latest 50 orders with metafields
------------------------------------------------------------------- */

import express from 'express';
import axios from 'axios';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();

/* ---------- ENV -------------------------------------------------- */
const {
  SHOPIFY_STORE_URL,        // like "nc0j5n-wa.myshopify.com" (NO https://)
  SHOPIFY_ACCESS_TOKEN,
  SHOPIFY_API_VERSION = '2024-07',
  FRONTEND_SECRET,
  PORT = 10000
} = process.env;

if (!SHOPIFY_STORE_URL || !SHOPIFY_ACCESS_TOKEN || !FRONTEND_SECRET) {
  console.error('❌ Missing env vars – check SHOPIFY_STORE_URL, SHOPIFY_ACCESS_TOKEN, FRONTEND_SECRET');
  process.exit(1);
}

/* ---------- APP -------------------------------------------------- */
const app = express();
app.use(cors());

/* ---------- Tiny Auth Middleware -------------------------------- */
app.use((req, res, next) => {
  if (req.headers['x-api-key'] !== FRONTEND_SECRET) {
    return res.status(403).send('Forbidden – invalid API key');
  }
  next();
});

/* ---------- Health Route ---------------------------------------- */
app.get('/health', (_, res) => res.send('OK ✅'));

/* ---------- Orders Route (GraphQL) ------------------------------ */
app.get('/orders', async (req, res) => {
  const afterCursor = req.query.cursor || null;
  const first = 50;

  const query = `
    query getOrders($first: Int!, $after: String) {
      orders(first: $first, after: $after, reverse: true) {
        edges {
          cursor
          node {
            id
            name
            createdAt
            displayFinancialStatus
            displayFulfillmentStatus
            totalPriceSet {
              shopMoney {
                amount
                currencyCode
              }
            }
            customer {
              firstName
              lastName
              email
            }
            metafields(first: 20, namespace: "custom") {
              edges {
                node {
                  key
                  value
                  type
                }
              }
            }
          }
        }
        pageInfo {
          hasNextPage
          hasPreviousPage
          endCursor
          startCursor
        }
      }
    }
  `;

  const variables = { first, after: afterCursor };

  try {
    const { data } = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
      { query, variables },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN
        }
      }
    );

    if (data.errors) {
      console.error('🔴 Shopify GraphQL returned errors:', JSON.stringify(data.errors, null, 2));
      return res.status(502).json({ errors: data.errors });
    }

    const shopifyOrders = data.data.orders;
    const orders = shopifyOrders.edges.map(({ cursor, node }) => {
      const metafields = {};
      node.metafields.edges.forEach(mf => {
        metafields[mf.node.key] = mf.node.value;
      });

      return {
        cursor,
        id: node.id,
        name: node.name,
        created_at: node.createdAt,
        financial_status: node.displayFinancialStatus,
        fulfillment_status: node.displayFulfillmentStatus,
        total_price: node.totalPriceSet.shopMoney.amount,
        currency: node.totalPriceSet.shopMoney.currencyCode,
        customer: node.customer,
        metafields
      };
    });

    res.json({
      orders,
      count: orders.length,
      next_cursor: shopifyOrders.pageInfo.hasNextPage ? shopifyOrders.pageInfo.endCursor : null,
      prev_cursor: shopifyOrders.pageInfo.hasPreviousPage ? shopifyOrders.pageInfo.startCursor : null
    });

  } catch (err) {
    console.error('🔴 Shopify GraphQL error (network/axios):', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to fetch orders via GraphQL' });
  }
});

/* ---------- Start Server ---------------------------------------- */
app.listen(PORT, () => {
  console.log(`✅ Shopify proxy is running → http://localhost:${PORT} → ${SHOPIFY_STORE_URL}`);
});
