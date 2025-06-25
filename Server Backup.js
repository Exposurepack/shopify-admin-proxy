import express from "express";
import axios from "axios";
import cors from "cors";
import dotenv from "dotenv";
dotenv.config();

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

const app = express();
app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
  if (req.headers["x-api-key"] !== FRONTEND_SECRET) {
    return res.status(403).send("Forbidden – bad API key");
  }
  next();
});

app.get("/health", (_, res) => res.send("OK ✅"));

app.get("/orders", async (req, res) => {
  try {
    const restRes = await axios.get(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/orders.json?limit=50&status=any`,
      {
        headers: {
          "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        },
      }
    );

    const noteMap = {};
    restRes.data.orders.forEach((order) => {
      const notes = {};
      order.note_attributes.forEach((na) => {
        notes[na.name] = na.value;
      });
      noteMap[order.id] = notes;
    });

    const gqlQuery = `
      query getOrders($first: Int!) {
        orders(first: $first, reverse: true) {
          edges {
            cursor
            node {
              id
              name
              legacyResourceId
              createdAt
              displayFinancialStatus
              displayFulfillmentStatus
              totalPriceSet {
                shopMoney {
                  amount
                  currencyCode
                }
              }
              lineItems(first: 50) {
                edges {
                  node {
                    title
                    quantity
                    sku
                    variantTitle
                    vendor
                    product {
                      title
                      productType
                    }
                  }
                }
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
            endCursor
          }
        }
      }
    `;

    const gqlRes = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
      { query: gqlQuery, variables: { first: 50 } },
      {
        headers: {
          "Content-Type": "application/json",
          "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        },
      }
    );

    if (gqlRes.data.errors) {
      console.error("🔴 GraphQL Errors:", gqlRes.data.errors);
      return res.status(502).json({ errors: gqlRes.data.errors });
    }

    const orders = gqlRes.data.data.orders.edges.map(({ cursor, node }) => {
      const metafields = {};
      node.metafields.edges.forEach((mf) => {
        metafields[mf.node.key] = mf.node.value;
      });

      const lineItems = node.lineItems.edges.map((item) => ({
        title: item.node.title,
        sku: item.node.sku,
        quantity: item.node.quantity,
        variantTitle: item.node.variantTitle,
        vendor: item.node.vendor,
        productTitle: item.node.product?.title,
        productType: item.node.product?.productType,
      }));

      return {
        cursor,
        id: node.id,
        legacy_id: node.legacyResourceId,
        name: node.name,
        created_at: node.createdAt,
        financial_status: node.displayFinancialStatus,
        fulfillment_status: node.displayFulfillmentStatus,
        total_price: node.totalPriceSet.shopMoney.amount,
        currency: node.totalPriceSet.shopMoney.currencyCode,
        metafields,
        attributes: noteMap[node.legacyResourceId] || {},
        line_items: lineItems,
      };
    });

    res.json({
      orders,
      count: orders.length,
      next_cursor: gqlRes.data.data.orders.pageInfo.hasNextPage
        ? gqlRes.data.data.orders.pageInfo.endCursor
        : null,
    });
  } catch (err) {
    console.error("🔴 Order fetch error:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});

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

app.listen(PORT, () => {
  console.log(`✅  GraphQL + REST proxy running on http://localhost:${PORT} → ${SHOPIFY_STORE_URL}`);
});
