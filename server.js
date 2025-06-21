import express from 'express';
import axios from 'axios';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();

/* ---------- ENV -------------------------------------------------- */
const {
  SHOPIFY_STORE_URL,
  SHOPIFY_ACCESS_TOKEN,
  SHOPIFY_API_VERSION = '2024-04',
  FRONTEND_SECRET,
  PORT = 10000
} = process.env;

if (!SHOPIFY_STORE_URL || !SHOPIFY_ACCESS_TOKEN || !FRONTEND_SECRET) {
  console.error('❌ Missing env vars → SHOPIFY_STORE_URL, SHOPIFY_ACCESS_TOKEN, FRONTEND_SECRET');
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

/* ---------- Health Check ---------------------------------------- */
app.get('/health', (_, res) => res.send('OK ✅'));

/* ---------- GraphQL Orders Route -------------------------------- */
app.get('/orders', async (req, res) => {
  const query = `
    {
      orders(first: 25, reverse: true) {
        edges {
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
            metafields(first: 10, namespace: "custom") {
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
      }
    }
  `;

  try {
    const { data } = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
      { query },
      {
        headers: {
          'Content-Type': 'application/json',
          'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN
        }
      }
    );

    const orders = data.data.orders.edges.map(edge => {
      const order = edge.node;
      const metafields = {};
      order.metafields.edges.forEach(mf => {
        metafields[mf.node.key] = mf.node.value;
      });

      return {
        id: order.id,
        name: order.name,
        created_at: order.createdAt,
        financial_status: order.financialStatus,
        fulfillment_status: order.fulfillmentStatus,
        total_price: order.totalPriceSet.shopMoney.amount,
        currency: order.totalPriceSet.shopMoney.currencyCode,
        customer: order.customer,
        metafields
      };
    });

    res.json({ orders, count: orders.length });

  } catch (err) {
    console.error('🔴 Shopify GraphQL error:', err.response?.data || err.message);
    res.status(500).json({ error: 'Failed to fetch orders via GraphQL' });
  }
});

/* ---------- Start Server ---------------------------------------- */
app.listen(PORT, () => {
  console.log(`✅ GraphQL proxy running on http://localhost:${PORT} → ${SHOPIFY_STORE_URL}`);
});
