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

  // 🔴 If value is empty, attempt to DELETE the metafield instead
  if (value === "") {
    const getMetafieldsQuery = `
      query GetMetafieldID($ownerId: ID!, $namespace: String!, $key: String!) {
        metafield(ownerId: $ownerId, namespace: $namespace, key: $key) {
          id
        }
      }
    `;

    try {
      const lookupRes = await axios.post(
        `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
        {
          query: getMetafieldsQuery,
          variables: { ownerId: orderGID, namespace, key },
        },
        {
          headers: {
            "Content-Type": "application/json",
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
          },
        }
      );

      const metafieldId = lookupRes.data?.data?.metafield?.id;

      if (!metafieldId) {
        console.log(`ℹ️ No metafield to delete for ${namespace}.${key}`);
        return res.json({ success: true, deleted: false });
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

      if (deleteRes.data.data.metafieldDelete.userErrors.length > 0) {
        console.error("🔴 Metafield delete error:", deleteRes.data.data.metafieldDelete.userErrors);
        return res.status(502).json({ errors: deleteRes.data.data.metafieldDelete.userErrors });
      }

      return res.json({ success: true, deleted: true });
    } catch (err) {
      console.error("🔴 Metafield DELETE error:", err.response?.data || err.message);
      return res.status(500).json({ error: "Failed to delete metafield" });
    }
  }

  // 🟢 Normal write flow continues below
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
      console.error("🔴 Metafield write error:", data.errors || data.data.metafieldsSet.userErrors);
      return res.status(502).json({ errors: data.errors || data.data.metafieldsSet.userErrors });
    }

    res.json({ success: true, metafields: data.data.metafieldsSet.metafields });
  } catch (err) {
    console.error("🔴 Metafield POST error:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to write metafield" });
  }
});
