import express from "express";
import axios from "axios";
import cors from "cors";
import dotenv from "dotenv";
dotenv.config();

/* ---------- ENV -------------------------------------------------- */
const {
  SHOPIFY_STORE_URL,
  SHOPIFY_ACCESS_TOKEN,
  SHOPIFY_API_VERSION = "2024-04",
  FRONTEND_SECRET,
  PORT = 10000,
} = process.env;

if (!SHOPIFY_STORE_URL || !SHOPIFY_ACCESS_TOKEN || !FRONTEND_SECRET) {
  console.error("❌  Missing env vars – set SHOPIFY_STORE_URL, SHOPIFY_ACCESS_TOKEN, FRONTEND_SECRET");
  process.exit(1);
}

/* ---------- APP -------------------------------------------------- */
const app = express();
app.use(cors());
app.use(express.json());

/* ---------- Tiny Auth ------------------------------------------- */
app.use((req, res, next) => {
  if (req.headers["x-api-key"] !== FRONTEND_SECRET) {
    return res.status(403).send("Forbidden – bad API key");
  }
  next();
});

/* ---------- Health Check ---------------------------------------- */
app.get("/health", (_, res) => res.send("OK ✅"));

/* ---------- /orders --------------------------------------------- */
app.get("/orders", async (req, res) => {
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
            noteAttributes {
              name
              value
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
          "Content-Type": "application/json",
          "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        },
      }
    );

    if (data.errors) {
      console.error("🔴  Shopify GraphQL errors:", JSON.stringify(data.errors, null, 2));
      return res.status(502).json({ errors: data.errors });
    }

    const shopifyOrders = data.data.orders;
    const orders = shopifyOrders.edges.map(({ cursor, node }) => {
      const metafields = {};
      node.metafields.edges.forEach((mf) => {
        metafields[mf.node.key] = mf.node.value;
      });

      const attributes = {};
      node.noteAttributes.forEach((attr) => {
        attributes[attr.name] = attr.value;
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
        metafields,
        attributes, // ✅ customer-entered values like business_name
      };
    });

    res.json({
      orders,
      count: orders.length,
      next_cursor: shopifyOrders.pageInfo.hasNextPage ? shopifyOrders.pageInfo.endCursor : null,
      prev_cursor: shopifyOrders.pageInfo.hasPreviousPage ? shopifyOrders.pageInfo.startCursor : null,
    });
  } catch (err) {
    console.error("🔴  Shopify GraphQL error (network/axios):", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to fetch orders via GraphQL" });
  }
});

/* ---------- /metafields (write) --------------------------------- */
app.post("/metafields", async (req, res) => {
  const { orderGID, key, value, type = "single_line_text_field", namespace = "custom" } = req.body;

  if (!orderGID || !key || typeof value === "undefined") {
    return res.status(400).json({ error: "Missing required fields: orderGID, key, value" });
  }

  const mutation = `
    mutation CreateMetafield($input: MetafieldsSetInput!) {
      metafieldsSet(metafields: [$input]) {
        metafields {
          key
          value
        }
        userErrors {
          field
          message
        }
      }
    }
  `;

  const variables = {
    input: {
      ownerId: orderGID,
      namespace,
      key,
      type,
      value: String(value),
    },
  };

  try {
    const { data } = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
      { query: mutation, variables },
      {
        headers: {
          "Content-Type": "application/json",
          "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        },
      }
    );

    if (data.errors || data.data.metafieldsSet.userErrors.length > 0) {
      console.error("🔴 Metafield write errors:", data.errors || data.data.metafieldsSet.userErrors);
      return res.status(502).json({ errors: data.errors || data.data.metafieldsSet.userErrors });
    }

    res.json({ success: true, written: data.data.metafieldsSet.metafields });
  } catch (err) {
    console.error("🔴 Metafield POST error:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to write metafield" });
  }
});

/* ---------- Start Server --------------------------------------- */
app.listen(PORT, () => {
  console.log(`✅  GraphQL proxy running on http://localhost:${PORT}  →  ${SHOPIFY_STORE_URL}`);
});
