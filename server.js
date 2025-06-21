/* ------------------------------------------------------------------
   Shopify Order Proxy  –  server.js  (GraphQL, Cursor-Paged)
   ------------------------------------------------------------------
   ▸ Uses Shopify GraphQL API (2024-04 or later)
   ▸ Handles authentication via x-api-key
   ▸ /health            – uptime ping
   ▸ /orders            – latest 50 orders + metafields (cursor-ready)
------------------------------------------------------------------- */

import express  from 'express';
import axios    from 'axios';
import cors     from 'cors';
import dotenv   from 'dotenv';
dotenv.config();

/* ---------- ENV -------------------------------------------------- */
const {
  SHOPIFY_STORE_URL,        // yourstore.myshopify.com (no https://)
  SHOPIFY_ACCESS_TOKEN,     // Shopify Admin API token
  SHOPIFY_API_VERSION = '2024-04',
  FRONTEND_SECRET,          // same value frontend sends in x-api-key
  PORT = 10000
} = process.env;

if (!SHOPIFY_STORE_URL || !SHOPIFY_ACCESS_TOKEN || !FRONTEND_SECRET) {
  console.error('❌ Missing required env vars → SHOPIFY_STORE_URL, SHOPIFY_ACCESS_TOKEN, FRONTEND_SECRET');
  process.exit(1);
}

/* ---------- INIT ------------------------------------------------- */
const app = express();
app.use(cors());

/* ---------- Middleware: API Key Auth ----------------------------- */
app.use((req, res, next) => {
  if (req.headers['x-api-key'] !== FRONTEND_SECRET) {
    return res.status(403).send('Forbidden – invalid API key');
  }
  next();
});

/* ---------- /health --------------------------------------------- */
app.get('/health', (_, res) => res.send('OK ✅'));

/* ---------- /orders (GraphQL with cursor pagination) ------------ */
app.get('/orders', async (req, res) => {
  const afterCursor = req.query.cursor || null;
  const first       = 50;

  const query = `
    query getOrders($first: Int!, $after: String) {
      orders(first: $first, after: $after, reverse: true) {
        edges {
          cursor
          node {
            id
            name
            createdAt
            financialStatus
            fulfillmentStatus
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
      node.metafields.edges.forEach(({ node: mf }) => {
        metafields[mf.key] = mf.value;
      });

      return {
        cursor,
        id: node.id,
        name: node.name,
        created_at: node.createdAt,
        financial_status: node.financialStatus,
        fulfillment_status: node.fulfillmentStatus,
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

/* ---------- Start ----------------------------------------------- */
app.listen(PORT, () => {
  console.log(`✅ Shopify proxy running at http://localhost:${PORT}  →  ${SHOPIFY_STORE_URL}`);
});
