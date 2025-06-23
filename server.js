/* ------------------------------------------------------------------
   Shopify Order Proxy – HYBRID (REST for address, GraphQL for metafields)
   ------------------------------------------------------------------ */

import express from "express";
import axios   from "axios";
import cors    from "cors";
import dotenv  from "dotenv";
dotenv.config();

/* ---------- ENV -------------------------------------------------- */
const {
  SHOPIFY_STORE_URL,            // mystore.myshopify.com  (NO https://)
  SHOPIFY_ACCESS_TOKEN,         // Admin-API token
  SHOPIFY_API_VERSION = "2024-04",
  FRONTEND_SECRET,              // value FE sends in x-api-key
  PORT = 10000
} = process.env;

if (!SHOPIFY_STORE_URL || !SHOPIFY_ACCESS_TOKEN || !FRONTEND_SECRET) {
  console.error("❌  Missing env vars – set SHOPIFY_STORE_URL, SHOPIFY_ACCESS_TOKEN, FRONTEND_SECRET");
  process.exit(1);
}

/* ---------- APP -------------------------------------------------- */
const app = express();
app.use(cors());

/* ---------- Tiny auth ------------------------------------------- */
app.use((req, res, next) => {
  if (req.headers["x-api-key"] !== FRONTEND_SECRET) {
    return res.status(403).send("Forbidden – bad API key");
  }
  next();
});

/* ---------- Health Check ---------------------------------------- */
app.get("/health", (_, res) => res.send("OK ✅"));

/* ---------- /orders (HYBRID) ------------------------------------ */
app.get("/orders", async (req, res) => {
  const sinceId = req.query.since_id || 0;

  const restURL = `https://${SHOPIFY_STORE_URL}` +
    `/admin/api/${SHOPIFY_API_VERSION}/orders.json` +
    `?limit=50&since_id=${sinceId}&status=any&order=created_at desc` +
    `&fields=id,name,created_at,financial_status,fulfillment_status,` +
    `total_price,currency,shipping_address`;

  try {
    const restRes = await axios.get(restURL, {
      headers: { "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN }
    });
    const restOrders = restRes.data.orders;

    let metaMap = {};

    if (restOrders.length > 0) {
      const gids = restOrders.map(o => `"gid://shopify/Order/${o.id}"`);
      const gql = `
        query meta($ids: [ID!]!) {
          nodes(ids: $ids) {
            ... on Order {
              id
              metafields(first: 20, namespace: "custom") {
                edges { node { key value type } }
              }
            }
          }
        }
      `;

      try {
        const gqlRes = await axios.post(
          `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
          { query: gql, variables: { ids: gids } },
          {
            headers: {
              "Content-Type": "application/json",
              "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN
            }
          }
        );

        if (gqlRes.data?.data?.nodes) {
          gqlRes.data.data.nodes.forEach(n => {
            const mfs = {};
            n.metafields?.edges.forEach(e => { mfs[e.node.key] = e.node.value; });
            metaMap[n.id] = mfs;
          });
        } else {
          console.warn("⚠️  No nodes returned from GraphQL metafield query");
        }
      } catch (gqlErr) {
        console.error("🔴  GraphQL metafield fetch failed:", gqlErr.response?.data || gqlErr.message);
      }
    }

    const orders = restOrders.map(o => {
      const gid  = `gid://shopify/Order/${o.id}`;
      const ship = o.shipping_address || {};
      return {
        id                 : gid,
        name               : o.name,
        created_at         : o.created_at,
        financial_status   : o.financial_status,
        fulfillment_status : o.fulfillment_status,
        total_price        : o.total_price,
        currency           : o.currency,
        metafields         : metaMap[gid] || {},
        shipping_company   : ship.company        || "",
        shipping_state     : ship.province_code  || "",
        shipping_postcode  : ship.zip            || ""
      };
    });

    const nextSinceId = orders.length
      ? orders[orders.length - 1].id.split("/").pop()
      : null;

    res.json({
      orders,
      count       : orders.length,
      next_cursor : nextSinceId
    });

  } catch (err) {
    console.error("🔴  Proxy error:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});

/* ---------- Start Server ---------------------------------------- */
app.listen(PORT, () => {
  console.log(`✅  Proxy running on http://localhost:${PORT}  →  ${SHOPIFY_STORE_URL}`);
});
