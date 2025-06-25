/* ---------- /orders --------------------------------------------- */
app.get("/orders", async (req, res) => {
  const first = 50;
  const afterCursor = req.query.cursor || null;

  // GraphQL query (excluding note/noteAttributes)
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
    const gqlRes = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
      { query, variables },
      {
        headers: {
          "Content-Type": "application/json",
          "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        },
      }
    );

    if (gqlRes.data.errors) {
      console.error("🔴 GraphQL errors:", JSON.stringify(gqlRes.data.errors, null, 2));
      return res.status(502).json({ errors: gqlRes.data.errors });
    }

    const shopifyOrders = gqlRes.data.data.orders;

    // Fetch REST orders (for notes)
    const restRes = await axios.get(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/orders.json?limit=${first}&status=any&order=created_at desc`,
      {
        headers: {
          "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        },
      }
    );

    const restOrders = restRes.data.orders;

    const orders = shopifyOrders.edges.map(({ cursor, node }) => {
      const metafields = {};
      node.metafields.edges.forEach((mf) => {
        metafields[mf.node.key] = mf.node.value;
      });

      const restMatch = restOrders.find((r) => r.name === node.name);
      const attributes = {};
      if (restMatch?.note_attributes) {
        restMatch.note_attributes.forEach((attr) => {
          attributes[attr.name] = attr.value;
        });
      }

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
        attributes, // ✅ pulled from REST
        note: restMatch?.note || "", // Optional note field from REST
      };
    });

    res.json({
      orders,
      count: orders.length,
      next_cursor: shopifyOrders.pageInfo.hasNextPage ? shopifyOrders.pageInfo.endCursor : null,
      prev_cursor: shopifyOrders.pageInfo.hasPreviousPage ? shopifyOrders.pageInfo.startCursor : null,
    });
  } catch (err) {
    console.error("🔴 Order fetch failed:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to fetch orders" });
  }
});
