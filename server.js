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
  console.error("\u274c Missing env vars: SHOPIFY_STORE_URL, SHOPIFY_ACCESS_TOKEN, FRONTEND_SECRET");
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json());

app.use((req, res, next) => {
  if (req.headers["x-api-key"] !== FRONTEND_SECRET) {
    return res.status(403).send("Forbidden – Invalid API key");
  }
  next();
});

app.get("/health", (_, res) => res.send("OK ✅"));

app.get("/metafields", (_, res) => {
  res.status(200).send("Metafields endpoint ready. Use POST to write data.");
});

app.post("/metafields", async (req, res) => {
  console.log("Incoming /metafields request:", req.body);

  const { orderGID, key, value, type = "single_line_text_field", namespace = "custom" } = req.body;

  if (!orderGID || !key || typeof value === "undefined") {
    console.error("400 Bad Request: Missing required fields", { orderGID, key, value });
    return res.status(400).json({ error: "Missing required fields: orderGID, key, value" });
  }

  if (!/^gid:\/\/shopify\/Order\/\d+$/.test(orderGID)) {
    console.error("400 Bad Request: Invalid orderGID format", { orderGID });
    return res.status(400).json({ error: "Invalid orderGID format. Must be gid://shopify/Order/ORDER_ID" });
  }

  if (value === "") {
    const lookupQuery = `
      query GetMetafieldID($ownerId: ID!, $namespace: String!, $key: String!) {
        metafield(ownerId: $ownerId, namespace: $namespace, key: $key) {
          id
        }
      }
    `;

    try {
      const lookup = await axios.post(
        `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
        {
          query: lookupQuery,
          variables: { ownerId: orderGID, namespace, key },
        },
        {
          headers: {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
          },
        }
      );

      const metafieldId = lookup.data?.data?.metafield?.id;
      if (!metafieldId) {
        return res.json({ success: true, deleted: false, message: "No metafield to delete" });
      }

      const deleteMutation = `
        mutation DeleteMetafield($id: ID!) {
          metafieldDelete(input: { id: $id }) {
            deletedId
            userErrors { field message }
          }
        }
      `;

      const deleteRes = await axios.post(
        `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
        {
          query: deleteMutation,
          variables: { id: metafieldId },
        },
        {
          headers: {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
          },
        }
      );

      const errors = deleteRes.data?.data?.metafieldDelete?.userErrors;
      if (errors?.length > 0) {
        console.error("\ud83d\udd34 Metafield delete error:", errors);
        return res.status(502).json({ errors });
      }

      return res.json({ success: true, deleted: true });
    } catch (err) {
      console.error("\ud83d\udd34 Metafield DELETE error:", err.response?.data || err.message);
      return res.status(500).json({ error: "Failed to delete metafield" });
    }
  }

  const mutation = `
    mutation SetMetafields($input: MetafieldsSetInput!) {
      metafieldsSet(metafields: [$input]) {
        metafields { key value }
        userErrors { field message }
      }
    }
  `;

  const variables = {
    input: { ownerId: orderGID, namespace, key, type, value: String(value) },
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
      console.error("\ud83d\udd34 Metafield write error:", data.errors || data.data.metafieldsSet.userErrors);
      return res.status(502).json({ errors: data.errors || data.data.metafieldsSet.userErrors });
    }

    res.json({ success: true, metafields: data.data.metafieldsSet.metafields });
  } catch (err) {
    console.error("\ud83d\udd34 Metafield POST error:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to write metafield" });
  }
});

app.post("/webhooks/fulfillment", async (req, res) => {
  try {
    const orderId = req.body?.order_id;
    if (!orderId) return res.status(400).send("Missing order_id in webhook body");

    const orderGID = `gid://shopify/Order/${orderId}`;
    const melbourneDate = new Date().toLocaleString("en-AU", { timeZone: "Australia/Melbourne" });
    const isoDate = new Date(melbourneDate).toISOString();

    const mutation = `
      mutation SetMetafields($input: MetafieldsSetInput!) {
        metafieldsSet(metafields: [$input]) {
          metafields { key value }
          userErrors { field message }
        }
      }
    `;

    const variables = {
      input: {
        ownerId: orderGID,
        namespace: "custom",
        key: "ready_for_dispatch_date_time",
        type: "date_time",
        value: isoDate,
      },
    };

    const response = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
      { query: mutation, variables },
      {
        headers: {
          "Content-Type": "application/json",
          "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        },
      }
    );

    if (response.data.errors || response.data.data.metafieldsSet.userErrors.length > 0) {
      console.error("\ud83d\udd34 Webhook metafield write error:", response.data.errors || response.data.data.metafieldsSet.userErrors);
      return res.status(502).json({ errors: response.data.errors || response.data.data.metafieldsSet.userErrors });
    }

    res.status(200).send("Webhook processed and metafield updated");
  } catch (err) {
    console.error("\ud83d\udd34 Webhook error:", err.response?.data || err.message);
    res.status(500).send("Webhook failed");
  }
});

app.listen(PORT, () => {
  console.log(`\u2705 Admin proxy server running at http://localhost:${PORT} for \u2192 ${SHOPIFY_STORE_URL}`);
});
