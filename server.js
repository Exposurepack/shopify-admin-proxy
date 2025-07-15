import express from "express";
import axios from "axios";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import FormData from "form-data";
dotenv.config();

const {
  SHOPIFY_STORE_URL,
  SHOPIFY_ACCESS_TOKEN,
  SHOPIFY_API_VERSION = "2024-04",
  FRONTEND_SECRET,
  PORT = 10000,
} = process.env;

if (!SHOPIFY_STORE_URL || !SHOPIFY_ACCESS_TOKEN || !FRONTEND_SECRET) {
  console.error("❌ Missing env vars: SHOPIFY_STORE_URL, SHOPIFY_ACCESS_TOKEN, FRONTEND_SECRET");
  process.exit(1);
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Configure multer for file uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Allow images and design files
    const allowedTypes = /jpeg|jpg|png|gif|pdf|ai|eps|svg|psd/;
    const extname = allowedTypes.test(file.originalname.toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype) || 
                    file.mimetype === 'application/pdf' ||
                    file.mimetype === 'application/postscript' ||
                    file.mimetype === 'image/svg+xml';
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Only images and design files are allowed'));
    }
  }
});

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

// Support POST /metafield (singular) for compatibility
app.post("/metafield", (req, res, next) => {
  // Forward to /metafields handler
  req.url = "/metafields";
  app._router.handle(req, res, next);
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
    console.log(`🔍 Looking up metafield for deletion: ownerId=${orderGID}, namespace=${namespace}, key=${key}`);
    
    const lookupQuery = `
      query GetMetafieldID($ownerId: ID!, $namespace: String!, $key: String!) {
        node(id: $ownerId) {
          ... on Order {
            metafield(namespace: $namespace, key: $key) {
              id
              namespace
              key
              value
            }
          }
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

      console.log(`🔍 Lookup response:`, JSON.stringify(lookup.data, null, 2));
      
      const metafieldId = lookup.data?.data?.node?.metafield?.id;
      if (!metafieldId) {
        console.log(`❌ No metafield found for deletion with ownerId=${orderGID}, namespace=${namespace}, key=${key}`);
        
        // Let's list all metafields for this order to see what exists
        const listQuery = `
          query ListMetafields($ownerId: ID!) {
            node(id: $ownerId) {
              ... on Order {
                metafields(first: 50) {
                  edges {
                    node {
                      id
                      namespace
                      key
                      value
                      type
                    }
                  }
                }
              }
            }
          }
        `;
        
        try {
          const listRes = await axios.post(
            `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
            {
              query: listQuery,
              variables: { ownerId: orderGID },
            },
            {
              headers: {
                "Content-Type": "application/json",
                "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
              },
            }
          );
          
          console.log(`📋 All metafields for order ${orderGID}:`, JSON.stringify(listRes.data?.data?.node?.metafields, null, 2));
        } catch (listErr) {
          console.log(`❌ Failed to list metafields:`, listErr.message);
        }
        
        return res.json({ success: true, deleted: false, message: "No metafield to delete" });
      }
      
      console.log(`✅ Found metafield to delete: ${metafieldId}`);
      

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
        console.error("🔴 Metafield delete error:", errors);
        return res.status(502).json({ errors });
      }

      return res.json({ success: true, deleted: true });
    } catch (err) {
      console.error("🔴 Metafield DELETE error:", err.response?.data || err.message);
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
      console.error("🔴 Metafield write error:", data.errors || data.data.metafieldsSet.userErrors);
      return res.status(502).json({ errors: data.errors || data.data.metafieldsSet.userErrors });
    }

    res.json({ success: true, metafields: data.data.metafieldsSet.metafields });
  } catch (err) {
    console.error("🔴 Metafield POST error:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to write metafield" });
  }
});

// File upload endpoint using Shopify's File API
app.post("/upload-file", upload.single('file'), async (req, res) => {
  console.log("Incoming /upload-file request");

  if (!req.file) {
    return res.status(400).json({ error: "No file provided" });
  }

  const { orderGID, filename } = req.body;

  if (!orderGID) {
    return res.status(400).json({ error: "Missing orderGID" });
  }

  if (!/^gid:\/\/shopify\/Order\/\d+$/.test(orderGID)) {
    return res.status(400).json({ error: "Invalid orderGID format. Must be gid://shopify/Order/ORDER_ID" });
  }

  try {
    console.log(`📁 Uploading file: ${req.file.originalname} (${req.file.size} bytes)`);

    // Step 1: Create a staged upload URL
    const stagedUploadMutation = `
      mutation StagedUploadCreate($input: [StagedUploadInput!]!) {
        stagedUploadsCreate(input: $input) {
          stagedTargets {
            url
            resourceUrl
            parameters { name value }
          }
          userErrors { field message }
        }
      }
    `;

    const uploadInput = {
      filename: filename || req.file.originalname,
      mimeType: req.file.mimetype,
      resource: "FILE"
    };

    const stagedUploadRes = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
      {
        query: stagedUploadMutation,
        variables: { input: [uploadInput] }
      },
      {
        headers: {
          "Content-Type": "application/json",
          "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        },
      }
    );

    if (stagedUploadRes.data.errors || stagedUploadRes.data.data.stagedUploadsCreate.userErrors.length > 0) {
      console.error("🔴 Staged upload error:", stagedUploadRes.data.errors || stagedUploadRes.data.data.stagedUploadsCreate.userErrors);
      return res.status(502).json({ error: "Failed to create staged upload" });
    }

    const stagedTarget = stagedUploadRes.data.data.stagedUploadsCreate.stagedTargets[0];
    console.log("✅ Staged upload URL created:", stagedTarget.url);

    // Step 2: Upload the file to the staged URL
    // For Google Cloud Storage, we need to upload as binary data, not multipart form
    const uploadResponse = await axios.put(stagedTarget.url, req.file.buffer, {
      headers: {
        'Content-Type': req.file.mimetype,
        'Content-Length': req.file.size.toString()
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      timeout: 30000 // 30 second timeout
    });

    console.log("✅ File uploaded to staged URL, status:", uploadResponse.status);

    // Step 3: Create the file in Shopify using the staged upload
    const fileCreateMutation = `
      mutation FileCreate($files: [FileCreateInput!]!) {
        fileCreate(files: $files) {
          files {
            id
            url
            fileStatus
            alt
          }
          userErrors { field message }
        }
      }
    `;

    const fileInput = {
      originalSource: stagedTarget.resourceUrl,
      filename: req.file.originalname,
      alt: `Design file for order ${orderGID}`
    };

    const fileCreateRes = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
      {
        query: fileCreateMutation,
        variables: { files: [fileInput] }
      },
      {
        headers: {
          "Content-Type": "application/json",
          "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        },
      }
    );

    if (fileCreateRes.data.errors || fileCreateRes.data.data.fileCreate.userErrors.length > 0) {
      console.error("🔴 File create error:", fileCreateRes.data.errors || fileCreateRes.data.data.fileCreate.userErrors);
      return res.status(502).json({ error: "Failed to create file in Shopify" });
    }

    const createdFile = fileCreateRes.data.data.fileCreate.files[0];
    console.log("✅ File created in Shopify:", createdFile.id, createdFile.url);

    // Step 4: Save the file URL to the order metafield
    const fileMetadata = {
      id: createdFile.id,
      url: createdFile.url,
      filename: req.file.originalname,
      size: req.file.size,
      type: req.file.mimetype,
      uploadedAt: new Date().toISOString()
    };

    const metafieldPayload = {
      orderGID,
      key: 'design_artworks_file',
      value: JSON.stringify(fileMetadata),
      type: 'single_line_text_field',
      namespace: 'custom'
    };

    const metafieldResponse = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
      {
        query: `
          mutation SetMetafields($input: MetafieldsSetInput!) {
            metafieldsSet(metafields: [$input]) {
              metafields { key value }
              userErrors { field message }
            }
          }
        `,
        variables: { input: metafieldPayload }
      },
      {
        headers: {
          "Content-Type": "application/json",
          "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
        },
      }
    );

    if (metafieldResponse.data.errors || metafieldResponse.data.data.metafieldsSet.userErrors.length > 0) {
      console.error("🔴 Metafield save error:", metafieldResponse.data.errors || metafieldResponse.data.data.metafieldsSet.userErrors);
      return res.status(502).json({ error: "File uploaded but failed to save metafield" });
    }

    console.log("✅ File metadata saved to metafield");

    res.json({
      success: true,
      file: {
        id: createdFile.id,
        url: createdFile.url,
        filename: req.file.originalname,
        size: req.file.size,
        type: req.file.mimetype
      }
    });

  } catch (err) {
    console.error("🔴 File upload error:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to upload file" });
  }
});

// NEW: REST API endpoint for individual order details with full REST API data
app.get("/rest/orders/:legacyId", async (req, res) => {
  const { legacyId } = req.params;

  try {
    console.log('🔄 Fetching REST order details for legacy ID:', legacyId);

    // Fetch complete order details from Shopify REST API
    const response = await axios.get(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/orders/${legacyId}.json`,
      {
        headers: {
          'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN
        }
      }
    );

    const order = response.data.order;
    console.log('✅ REST order details fetched for:', order.name);

    res.json({ order });

  } catch (error) {
    console.error('❌ Error fetching REST order details:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to fetch order details' });
  }
});

// NEW: REST API endpoint for location details
app.get("/rest/locations", async (req, res) => {
  try {
    console.log('🔄 Fetching locations from Shopify REST API');

    // Fetch locations from Shopify REST API
    const response = await axios.get(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/locations.json`,
      {
        headers: {
          'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN
        }
      }
    );

    const locations = response.data.locations;
    console.log('✅ Fetched', locations.length, 'locations');

    res.json({ locations });

  } catch (error) {
    console.error('❌ Error fetching locations:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to fetch locations' });
  }
});

// Original GraphQL-based orders endpoint
app.get("/orders", async (req, res) => {
  try {
    const restRes = await axios.get(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/orders.json?limit=50&status=any`,
      { headers: { "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN } }
    );

    const noteMap = {};
    restRes.data.orders.forEach((order) => {
      const notes = {};
      order.note_attributes.forEach((na) => { notes[na.name] = na.value });
      noteMap[order.id] = notes;
    });

    const gqlQuery = `
      query GetOrders($first: Int!) {
        orders(first: $first, reverse: true) {
          edges {
            cursor
            node {
              id legacyResourceId name createdAt displayFinancialStatus displayFulfillmentStatus
              tags
              totalPriceSet { shopMoney { amount currencyCode } }
              lineItems(first: 50) {
                edges {
                  node {
                    title quantity sku variantTitle vendor
                    product { title productType }
                  }
                }
              }
              metafields(first: 20, namespace: "custom") {
                edges { node { key value type } }
              }
            }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    `;

    const gqlRes = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
      { query: gqlQuery, variables: { first: 50 } },
      { headers: { "Content-Type": "application/json", "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN } }
    );

    if (gqlRes.data.errors) {
      console.error("🔴 GraphQL Errors:", gqlRes.data.errors);
      return res.status(502).json({ errors: gqlRes.data.errors });
    }

    const orders = gqlRes.data.data.orders.edges.map(({ cursor, node }) => {
      const metafields = {};
      node.metafields.edges.forEach((mf) => { metafields[mf.node.key] = mf.node.value });

      const lineItems = node.lineItems.edges.map((item) => ({
        title: item.node.title,
        quantity: item.node.quantity,
        sku: item.node.sku,
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
        tags: node.tags || [],
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

// Original GraphQL-based single order endpoint
app.get("/orders/:legacyId", async (req, res) => {
  const { legacyId } = req.params;

  try {
    const gid = `gid://shopify/Order/${legacyId}`;

    const gqlQuery = `
      query GetOrder($id: ID!) {
        order(id: $id) {
          id
          legacyResourceId
          name
          createdAt
          displayFinancialStatus
          displayFulfillmentStatus
          tags
          totalPriceSet { shopMoney { amount currencyCode } }
          lineItems(first: 50) {
            edges {
              node {
                title quantity sku variantTitle vendor
                product { title productType }
              }
            }
          }
          metafields(first: 20, namespace: "custom") {
            edges { node { key value type } }
          }
        }
      }
    `;

    const gqlRes = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`,
      { query: gqlQuery, variables: { id: gid } },
      { headers: { "Content-Type": "application/json", "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN } }
    );

    if (gqlRes.data.errors) {
      console.error("🔴 GraphQL Error:", gqlRes.data.errors);
      return res.status(502).json({ errors: gqlRes.data.errors });
    }

    const node = gqlRes.data.data.order;
    const metafields = {};
    node.metafields.edges.forEach((mf) => { metafields[mf.node.key] = mf.node.value });

    const lineItems = node.lineItems.edges.map((item) => ({
      title: item.node.title,
      quantity: item.node.quantity,
      sku: item.node.sku,
      variantTitle: item.node.variantTitle,
      vendor: item.node.vendor,
      productTitle: item.node.product?.title,
      productType: item.node.product?.productType,
    }));

    // ✅ Add note_attributes from REST for single order
    const noteRes = await axios.get(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/orders/${legacyId}.json`,
      { headers: { "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN } }
    );

    const noteAttributes = {};
    noteRes.data.order.note_attributes.forEach((na) => {
      noteAttributes[na.name] = na.value;
    });

    res.json({
      id: node.id,
      legacy_id: node.legacyResourceId,
      name: node.name,
      created_at: node.createdAt,
      financial_status: node.displayFinancialStatus,
      fulfillment_status: node.displayFulfillmentStatus,
      tags: node.tags || [],
      total_price: node.totalPriceSet.shopMoney.amount,
      currency: node.totalPriceSet.shopMoney.currencyCode,
      metafields,
      attributes: noteAttributes,
      line_items: lineItems,
    });
  } catch (err) {
    console.error("🔴 /orders/:id error:", err.response?.data || err.message);
    res.status(500).json({ error: "Failed to fetch individual order" });
  }
});

// NEW: Create fulfillment endpoint
app.post("/fulfillments", async (req, res) => {
  console.log("Incoming /fulfillments request:", req.body);

  const { orderGID, trackingNumber, carrier, timestamp } = req.body;

  if (!orderGID || !trackingNumber || !carrier) {
    console.error("400 Bad Request: Missing required fields", { orderGID, trackingNumber, carrier });
    return res.status(400).json({ error: "Missing required fields: orderGID, trackingNumber, carrier" });
  }

  if (!/^gid:\/\/shopify\/Order\/\d+$/.test(orderGID)) {
    console.error("400 Bad Request: Invalid orderGID format", { orderGID });
    return res.status(400).json({ error: "Invalid orderGID format. Must be gid://shopify/Order/ORDER_ID" });
  }

  try {
    // Extract legacy order ID from GID
    const legacyOrderId = orderGID.split('/').pop();
    
    console.log(`🚚 Creating fulfillment for order ${legacyOrderId}`);

    // First, get the order to get all line items
    const orderResponse = await axios.get(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/orders/${legacyOrderId}.json`,
      {
        headers: {
          'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN
        }
      }
    );

    const order = orderResponse.data.order;
    
    console.log('🔍 Order location info:', {
      processing_location_id: order.processing_location_id,
      location_id: order.location_id,
      source_name: order.source_name,
      order_id: order.id
    });
    
    // Get all fulfillable line items
    const lineItems = order.line_items.filter(item => item.fulfillable_quantity > 0).map(item => ({
      id: item.id,
      quantity: item.fulfillable_quantity
    }));

    if (lineItems.length === 0) {
      console.error("❌ No fulfillable line items found");
      return res.status(400).json({ error: "No fulfillable line items found" });
    }

    // Get a valid location_id if the order doesn't have one
    let locationId = order.processing_location_id || order.location_id;
    
    if (!locationId) {
      console.log('⚠️ No location_id found in order, fetching store locations...');
      try {
        const locationsResponse = await axios.get(
          `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/locations.json`,
          {
            headers: {
              'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN
            }
          }
        );
        
        // Use the first active location
        const activeLocation = locationsResponse.data.locations.find(loc => loc.active);
        if (activeLocation) {
          locationId = activeLocation.id;
          console.log('✅ Using active location:', activeLocation.name, 'ID:', locationId);
        } else {
          console.error('❌ No active locations found');
          return res.status(400).json({ error: "No active locations found for fulfillment" });
        }
      } catch (locError) {
        console.error('❌ Error fetching locations:', locError.response?.data || locError.message);
        return res.status(500).json({ error: "Failed to fetch store locations" });
      }
    }

    // Create fulfillment
    const fulfillmentData = {
      fulfillment: {
        location_id: locationId,
        tracking_number: trackingNumber,
        tracking_company: carrier.toUpperCase(), // Convert to uppercase for Shopify compatibility
        tracking_urls: [],
        notify_customer: true,
        line_items: lineItems
      }
    };

    console.log('🚚 Creating fulfillment with data:', fulfillmentData);

    const fulfillmentResponse = await axios.post(
      `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/orders/${legacyOrderId}/fulfillments.json`,
      fulfillmentData,
      {
        headers: {
          'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN,
          'Content-Type': 'application/json'
        }
      }
    );

    console.log('✅ Fulfillment created:', fulfillmentResponse.data.fulfillment.id);

    res.json({ 
      success: true, 
      fulfillment: fulfillmentResponse.data.fulfillment 
    });

  } catch (error) {
    console.error('❌ Error creating fulfillment:', error.response?.data || error.message);
    
    if (error.response?.status === 422) {
      return res.status(422).json({ 
        error: 'Validation error', 
        details: error.response.data.errors 
      });
    }
    
    if (error.response?.status === 406) {
      return res.status(406).json({ 
        error: 'Request not acceptable', 
        details: error.response.data || 'The fulfillment request format is not acceptable to Shopify. Please check tracking_company and location_id values.' 
      });
    }
    
    res.status(500).json({ error: 'Failed to create fulfillment', details: error.response?.data || error.message });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Admin proxy server running at http://localhost:${PORT} for → ${SHOPIFY_STORE_URL}`);
  console.log('🔄 Available endpoints:');
  console.log('  - GraphQL: /orders, /orders/:id');
  console.log('  - REST: /rest/orders/:id, /rest/locations');
  console.log('  - Metafields: /metafields');
  console.log('  - Files: /upload-file');
  console.log('  - Fulfillments: /fulfillments');
}); 
