import express from "express";
import axios from "axios";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import FormData from "form-data";
import rateLimit from "express-rate-limit";
import helmet from "helmet";

dotenv.config();

// Environment variables with validation
const {
  SHOPIFY_STORE_URL,
  SHOPIFY_ACCESS_TOKEN,
  SHOPIFY_API_VERSION = "2024-10",
  FRONTEND_SECRET,
  PORT = 10000,
  NODE_ENV = "development"
} = process.env;

if (!SHOPIFY_STORE_URL || !SHOPIFY_ACCESS_TOKEN || !FRONTEND_SECRET) {
  console.error("❌ Missing required environment variables:");
  console.error("   - SHOPIFY_STORE_URL");
  console.error("   - SHOPIFY_ACCESS_TOKEN"); 
  console.error("   - FRONTEND_SECRET");
  process.exit(1);
}

// Security and performance configuration
const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // Allow for API usage
  crossOriginEmbedderPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: NODE_ENV === "production" ? 100 : 1000, // requests per window
  message: { error: "Too many requests, please try again later" },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// CORS configuration - Allow Shopify and custom domains
const corsOptions = {
  origin: NODE_ENV === "production" 
    ? [
        /\.myshopify\.com$/, 
        /localhost:\d+$/,
        'https://www.exposurepack.com.au',
        'https://exposurepack.com.au',
        /\.exposurepack\.com\.au$/
      ]
    : true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key'],
  credentials: true
};
app.use(cors(corsOptions));

// Body parsing with size limits
app.use(express.json({ 
  limit: '15mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// File upload configuration
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 25 * 1024 * 1024, // 25MB limit for design files
    files: 1
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|pdf|ai|eps|svg|psd|sketch|fig|indd/;
    const extname = allowedTypes.test(file.originalname.toLowerCase());
    const allowedMimeTypes = [
      'image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/svg+xml',
      'application/pdf', 'application/postscript', 'application/illustrator',
      'application/x-photoshop', 'image/vnd.adobe.photoshop'
    ];
    const mimetype = allowedMimeTypes.includes(file.mimetype) || file.mimetype.startsWith('image/');
    
    if (mimetype && extname) {
      cb(null, true);
    } else {
      cb(new Error(`Unsupported file type: ${file.mimetype}. Allowed: images, PDF, AI, EPS, SVG, PSD`));
    }
  }
});

// Authentication middleware
const authenticate = (req, res, next) => {
  const apiKey = req.headers["x-api-key"];
  if (!apiKey || apiKey !== FRONTEND_SECRET) {
    return res.status(401).json({ 
      error: "Unauthorized", 
      message: "Valid API key required in x-api-key header" 
    });
  }
  next();
};

app.use(authenticate);

// ===========================================
// HELPER FUNCTIONS FOR CLEANER CODE
// ===========================================

/**
 * Creates a standardized GraphQL client
 */
class ShopifyGraphQLClient {
  constructor() {
    this.endpoint = `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;
    this.headers = {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
    };
  }

  async query(query, variables = {}) {
    try {
      const response = await axios.post(this.endpoint, {
        query,
        variables
      }, { 
        headers: this.headers,
        timeout: 30000
      });

      if (response.data.errors) {
        throw new GraphQLError(response.data.errors);
      }

      return response.data;
    } catch (error) {
      if (error instanceof GraphQLError) throw error;
      throw new Error(`GraphQL request failed: ${error.message}`);
    }
  }

  async queryWithPagination(query, variables = {}, pageSize = 50) {
    let allResults = [];
    let hasNextPage = true;
    let cursor = null;

    while (hasNextPage) {
      const currentVariables = {
        ...variables,
        first: pageSize,
        ...(cursor && { after: cursor })
      };

      const data = await this.query(query, currentVariables);
      const connection = this.extractConnection(data);
      
      if (connection) {
        allResults = allResults.concat(connection.edges);
        hasNextPage = connection.pageInfo.hasNextPage;
        cursor = connection.pageInfo.endCursor;
      } else {
        hasNextPage = false;
      }
    }

    return allResults;
  }

  extractConnection(data) {
    // Helper to find the connection object in GraphQL response
    const findConnection = (obj) => {
      if (!obj || typeof obj !== 'object') return null;
      
      if (obj.edges && obj.pageInfo) return obj;
      
      for (const key in obj) {
        const result = findConnection(obj[key]);
        if (result) return result;
      }
      return null;
    };

    return findConnection(data.data);
  }
}

/**
 * Custom GraphQL Error class
 */
class GraphQLError extends Error {
  constructor(errors) {
    const message = Array.isArray(errors) 
      ? errors.map(e => e.message).join(', ')
      : errors.message || 'GraphQL Error';
    super(message);
    this.name = 'GraphQLError';
    this.graphQLErrors = errors;
  }
}

/**
 * REST API client for fallback operations
 */
class ShopifyRESTClient {
  constructor() {
    this.baseURL = `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}`;
    this.headers = {
      "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
      "Content-Type": "application/json"
    };
  }

  async get(endpoint) {
    const response = await axios.get(`${this.baseURL}${endpoint}`, {
      headers: this.headers,
      timeout: 30000
    });
    return response.data;
  }

  async post(endpoint, data) {
    const response = await axios.post(`${this.baseURL}${endpoint}`, data, {
      headers: this.headers,
      timeout: 30000
    });
    return response.data;
  }
}

/**
 * Metafield management utilities
 */
class MetafieldManager {
  constructor(graphqlClient) {
    this.client = graphqlClient;
  }

  async findMetafield(ownerId, namespace, key) {
    const query = `
      query GetMetafieldID($ownerId: ID!, $namespace: String!, $key: String!) {
        node(id: $ownerId) {
          ... on Order {
            metafield(namespace: $namespace, key: $key) {
              id
              namespace
              key
              value
              type
            }
          }
        }
      }
    `;

    const data = await this.client.query(query, { ownerId, namespace, key });
    return data.data?.node?.metafield;
  }

  async deleteMetafield(metafieldId) {
    // Extract numeric ID from GID format
    const numericId = metafieldId.replace('gid://shopify/Metafield/', '');
    
    try {
      // Use REST API for metafield deletion (more reliable across API versions)
      const response = await axios.delete(
        `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}/metafields/${numericId}.json`,
        {
          headers: {
            "X-Shopify-Access-Token": SHOPIFY_ACCESS_TOKEN,
            "Content-Type": "application/json"
          },
          timeout: 30000
        }
      );

      console.log(`✅ Successfully deleted metafield via REST: ${metafieldId}`);
      return { id: metafieldId };

    } catch (error) {
      if (error.response?.status === 404) {
        console.log(`ℹ️ Metafield not found (already deleted): ${metafieldId}`);
        return { id: metafieldId };
      }
      throw new Error(`Metafield deletion failed: ${error.response?.data?.errors || error.message}`);
    }
  }

  async setMetafield(ownerId, namespace, key, value, type = "single_line_text_field") {
    const mutation = `
      mutation SetMetafield($input: MetafieldsSetInput!) {
        metafieldsSet(metafields: [$input]) {
          metafields { 
            id
            key 
            value
            type
          }
          userErrors { 
            field 
            message 
          }
        }
      }
    `;

    const input = {
      ownerId,
      namespace,
      key,
      value: String(value),
      type
    };

    const data = await this.client.query(mutation, { input });
    const result = data.data.metafieldsSet;

    if (result.userErrors?.length > 0) {
      throw new Error(`Metafield update failed: ${result.userErrors.map(e => e.message).join(', ')}`);
    }

    return result.metafields?.[0];
  }

  async listMetafields(ownerId, namespace = "custom") {
    const query = `
      query ListMetafields($ownerId: ID!, $namespace: String!) {
        node(id: $ownerId) {
          ... on Order {
            metafields(first: 50, namespace: $namespace) {
              edges {
                node {
                  id
                  key
                  value
                  type
                  namespace
                }
              }
            }
          }
        }
      }
    `;

    const data = await this.client.query(query, { ownerId, namespace });
    return data.data?.node?.metafields?.edges || [];
  }
}

/**
 * File upload manager for Shopify Files API
 */
class FileUploadManager {
  constructor(graphqlClient) {
    this.client = graphqlClient;
  }

  async createStagedUpload(filename, mimeType) {
    const mutation = `
      mutation StagedUploadCreate($input: [StagedUploadInput!]!) {
        stagedUploadsCreate(input: $input) {
          stagedTargets {
            url
            resourceUrl
            parameters { 
              name 
              value 
            }
          }
          userErrors { 
            field 
            message 
          }
        }
      }
    `;

    const input = [{
      filename,
      mimeType,
      resource: "FILE",
      httpMethod: "PUT"
    }];

    const data = await this.client.query(mutation, { input });
    const result = data.data.stagedUploadsCreate;

    if (result.userErrors?.length > 0) {
      throw new Error(`Staged upload creation failed: ${result.userErrors.map(e => e.message).join(', ')}`);
    }

    return result.stagedTargets?.[0];
  }

  async uploadToStaged(stagedTarget, fileBuffer, mimeType) {
    const uploadResponse = await axios.put(stagedTarget.url, fileBuffer, {
      headers: {
        'Content-Type': mimeType,
        'Content-Length': fileBuffer.length.toString()
      },
      maxContentLength: Infinity,
      maxBodyLength: Infinity,
      timeout: 60000 // 60 second timeout for large files
    });

    if (uploadResponse.status !== 200) {
      throw new Error(`File upload failed with status: ${uploadResponse.status}`);
    }

    return uploadResponse;
  }

  async createFileInShopify(stagedTarget, filename, alt = null) {
    const mutation = `
      mutation FileCreate($files: [FileCreateInput!]!) {
        fileCreate(files: $files) {
          files {
            id
            url
            fileStatus
            alt
            createdAt
          }
          userErrors { 
            field 
            message 
          }
        }
      }
    `;

    const input = [{
      filename,
      originalSource: stagedTarget.resourceUrl,
      ...(alt && { alt })
    }];

    const data = await this.client.query(mutation, { input });
    const result = data.data.fileCreate;

    if (result.userErrors?.length > 0) {
      throw new Error(`File creation failed: ${result.userErrors.map(e => e.message).join(', ')}`);
    }

    return result.files?.[0];
  }
}

/**
 * Error handling utilities
 */
const handleError = (error, res, defaultMessage = "An error occurred") => {
  console.error("🔴 Error:", error);

  if (error instanceof GraphQLError) {
    return res.status(502).json({
      error: "GraphQL Error",
      details: error.graphQLErrors,
      message: error.message
    });
  }

  if (error.response?.status === 401) {
    return res.status(401).json({
      error: "Shopify Authentication Failed",
      message: "Invalid API credentials"
    });
  }

  if (error.response?.status === 429) {
    return res.status(429).json({
      error: "Rate Limited",
      message: "API rate limit exceeded, please try again later"
    });
  }

  if (error.code === 'ECONNABORTED') {
    return res.status(504).json({
      error: "Request Timeout",
      message: "The request took too long to complete"
    });
  }

  res.status(500).json({
    error: defaultMessage,
    message: error.message,
    ...(NODE_ENV === "development" && { stack: error.stack })
  });
};

/**
 * Validation utilities
 */
const validateOrderGID = (orderGID) => {
  if (!orderGID) {
    throw new Error("orderGID is required");
  }
  if (!/^gid:\/\/shopify\/Order\/\d+$/.test(orderGID)) {
    throw new Error("Invalid orderGID format. Must be gid://shopify/Order/ORDER_ID");
  }
  return true;
};

// ===========================================
// INITIALIZE CLIENTS
// ===========================================

const graphqlClient = new ShopifyGraphQLClient();
const restClient = new ShopifyRESTClient();
const metafieldManager = new MetafieldManager(graphqlClient);
const fileUploadManager = new FileUploadManager(graphqlClient);

// ===========================================
// API ENDPOINTS
// ===========================================

/**
 * Health check and metadata endpoint
 */
app.get("/meta", async (req, res) => {
  try {
    // Get store information
    const storeQuery = `
      query GetShopInfo {
        shop {
          name
          email
          domain
          plan {
            displayName
          }
          currencyCode
        }
      }
    `;

    const storeData = await graphqlClient.query(storeQuery);
    const shop = storeData.data.shop;

    res.json({
      server: {
        status: "healthy",
        version: "2.0.0",
        apiVersion: SHOPIFY_API_VERSION,
        environment: NODE_ENV,
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
      },
      shopify: {
        store: {
          name: shop.name,
          domain: shop.domain,
          email: shop.email,
          plan: shop.plan.displayName,
          currency: shop.currencyCode
        },
        api: {
          version: SHOPIFY_API_VERSION,
          endpoint: `https://${SHOPIFY_STORE_URL}/admin/api/${SHOPIFY_API_VERSION}`
        }
      },
      endpoints: {
        graphql: ["/orders", "/orders/:id"],
        rest: ["/rest/orders/:id", "/rest/locations"],
        metafields: ["/metafields"],
        files: ["/upload-file"],
        meta: ["/meta"]
      }
    });
  } catch (error) {
    handleError(error, res, "Failed to get server metadata");
  }
});

/**
 * Metafields endpoint with improved error handling
 */
app.get("/metafields", (req, res) => {
  res.json({
    message: "Metafields endpoint ready",
    usage: {
      "GET /metafields": "This help message",
      "POST /metafields": "Create or update metafield",
      "DELETE /metafields": "Delete metafield (send empty value)"
    },
    examples: {
      create: {
        method: "POST",
        body: {
          orderGID: "gid://shopify/Order/12345",
          key: "custom_field",
          value: "some value",
          type: "single_line_text_field",
          namespace: "custom"
        }
      },
      delete: {
        method: "POST", 
        body: {
          orderGID: "gid://shopify/Order/12345",
          key: "custom_field",
          value: "",
          namespace: "custom"
        }
      }
    }
  });
});

// Support POST /metafield (singular) for compatibility
app.post("/metafield", (req, res, next) => {
  req.url = "/metafields";
  next();
});

app.post("/metafields", async (req, res) => {
  try {
    console.log("📝 Incoming /metafields request:", req.body);

    const { 
      orderGID, 
      key, 
      value, 
      type = "single_line_text_field", 
      namespace = "custom" 
    } = req.body;

    if (!key) {
      return res.status(400).json({ error: "Missing required field: key" });
    }

    validateOrderGID(orderGID);

    // Handle deletion when value is empty
    if (value === "" || value === null || value === undefined) {
      console.log(`🗑️ Deleting metafield: ${namespace}.${key} for order ${orderGID}`);
      
      const existingMetafield = await metafieldManager.findMetafield(orderGID, namespace, key);
      
      if (!existingMetafield) {
        console.log("ℹ️ No metafield found to delete");
        return res.json({ 
          success: true, 
          deleted: false, 
          message: "No metafield exists to delete" 
        });
      }

      const deletedMetafield = await metafieldManager.deleteMetafield(existingMetafield.id);
      console.log(`✅ Successfully deleted metafield: ${deletedMetafield.id}`);
      
      return res.json({ 
        success: true, 
        deleted: true, 
        deletedId: deletedMetafield.id 
      });
    }

    // Handle creation/update
    console.log(`💾 Setting metafield: ${namespace}.${key} = ${value}`);
    const metafield = await metafieldManager.setMetafield(orderGID, namespace, key, value, type);
    
    console.log(`✅ Successfully set metafield: ${metafield.id}`);
    res.json({ 
      success: true, 
      metafield: {
        id: metafield.id,
        key: metafield.key,
        value: metafield.value,
        type: metafield.type
      }
    });

  } catch (error) {
    handleError(error, res, "Failed to manage metafield");
  }
});

/**
 * File upload endpoint with improved error handling and progress tracking
 */
app.post("/upload-file", upload.single('file'), async (req, res) => {
  try {
    console.log("📤 Incoming /upload-file request");

    if (!req.file) {
      return res.status(400).json({ error: "No file provided" });
    }

    const { orderGID, filename, alt } = req.body;
    validateOrderGID(orderGID);

    const actualFilename = filename || req.file.originalname;
    const fileSize = req.file.size;
    const mimeType = req.file.mimetype;

    console.log(`📁 Processing file: ${actualFilename} (${(fileSize / 1024 / 1024).toFixed(2)}MB, ${mimeType})`);

    // Step 1: Create staged upload
    console.log("⏳ Creating staged upload target...");
    const stagedTarget = await fileUploadManager.createStagedUpload(actualFilename, mimeType);
    console.log("✅ Staged upload target created");

    // Step 2: Upload file to staged URL
    console.log("⏳ Uploading file to staged target...");
    await fileUploadManager.uploadToStaged(stagedTarget, req.file.buffer, mimeType);
    console.log("✅ File uploaded to staged target");

    // Step 3: Create file in Shopify
    console.log("⏳ Creating file record in Shopify...");
    const shopifyFile = await fileUploadManager.createFileInShopify(stagedTarget, actualFilename, alt);
    console.log(`✅ File created in Shopify: ${shopifyFile.id}`);

    // Step 4: Save file URL to order metafield
    console.log("⏳ Saving file reference to order metafields...");
    const metafieldKey = `uploaded_file_${Date.now()}`;
    const fileMetadata = {
      fileId: shopifyFile.id,
      url: shopifyFile.url,
      filename: actualFilename,
      uploadedAt: new Date().toISOString(),
      size: fileSize,
      mimeType: mimeType
    };

    await metafieldManager.setMetafield(
      orderGID,
      "custom",
      metafieldKey,
      JSON.stringify(fileMetadata),
      "json"
    );

    console.log("✅ File upload completed successfully");

    res.json({
      success: true,
      file: {
        id: shopifyFile.id,
        url: shopifyFile.url,
        filename: actualFilename,
        status: shopifyFile.fileStatus,
        size: fileSize,
        mimeType: mimeType,
        metafieldKey: metafieldKey
      }
    });

  } catch (error) {
    handleError(error, res, "File upload failed");
  }
});

/**
 * GraphQL orders endpoint with enhanced pagination support
 */
app.get("/orders", async (req, res) => {
  try {
    console.log("📋 Fetching orders with enhanced pagination...");

    const { 
      limit = 50, 
      status = "any", 
      paginate = "false",
      after,
      financial_status,
      fulfillment_status
    } = req.query;

    const pageSize = Math.min(parseInt(limit), 250); // Shopify max per page
    const shouldPaginate = paginate === "true";

    // Build dynamic query filters
    let statusFilter = "";
    if (status !== "any") {
      statusFilter = `query: "${status === "open" ? "status:open" : "status:closed"}"`;
    }

    if (financial_status) {
      statusFilter += statusFilter ? ` AND financial_status:${financial_status}` : `query: "financial_status:${financial_status}"`;
    }

    if (fulfillment_status) {
      statusFilter += statusFilter ? ` AND fulfillment_status:${fulfillment_status}` : `query: "fulfillment_status:${fulfillment_status}"`;
    }

    const ordersQuery = `
      query GetOrders($first: Int!${after ? ', $after: String' : ''}${statusFilter ? ', $query: String!' : ''}) {
        orders(first: $first${after ? ', after: $after' : ''}${statusFilter ? ', query: $query' : ''}, sortKey: CREATED_AT, reverse: true) {
          edges {
            node {
              id
              legacyResourceId
              name
              createdAt
              updatedAt
              tags
              note
              displayFinancialStatus
              displayFulfillmentStatus
              totalPriceSet {
                shopMoney {
                  amount
                  currencyCode
                }
              }
              customer {
                id
                displayName
                email
                phone
              }
              shippingAddress {
                firstName
                lastName
                company
                address1
                address2
                city
                province
                country
                zip
              }
              lineItems(first: 10) {
                edges {
                  node {
                    title
                    quantity
                    sku
                    variantTitle
                    vendor
                    originalUnitPriceSet {
                      shopMoney {
                        amount
                        currencyCode
                      }
                    }
                    discountedUnitPriceSet {
                      shopMoney {
                        amount
                        currencyCode
                      }
                    }
                    originalTotalSet {
                      shopMoney {
                        amount
                        currencyCode
                      }
                    }
                    discountedTotalSet {
                      shopMoney {
                        amount
                        currencyCode
                      }
                    }
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
            hasPreviousPage
            startCursor
            endCursor
          }
        }
      }
    `;

    let orders;
    const variables = { first: pageSize };
    
    if (after) variables.after = after;
    if (statusFilter) variables.query = statusFilter.replace('query: "', '').replace('"', '');

    if (shouldPaginate) {
      console.log("🔄 Using pagination to fetch all orders...");
      orders = await graphqlClient.queryWithPagination(ordersQuery, variables, pageSize);
    } else {
      const data = await graphqlClient.query(ordersQuery, variables);
      orders = data.data.orders.edges;
    }

    // Transform the data
    const transformedOrders = orders.map(({ node }) => {
      const metafields = {};
      node.metafields.edges.forEach((mf) => {
        metafields[mf.node.key] = mf.node.value;
      });

      const lineItems = node.lineItems.edges.map((item) => ({
        title: item.node.title,
        quantity: item.node.quantity,
        sku: item.node.sku,
        variantTitle: item.node.variantTitle,
        vendor: item.node.vendor,
        productTitle: item.node.product?.title,
        productType: item.node.product?.productType,
        unit_price: item.node.discountedUnitPriceSet?.shopMoney?.amount || item.node.originalUnitPriceSet?.shopMoney?.amount,
        line_price: item.node.discountedTotalSet?.shopMoney?.amount || item.node.originalTotalSet?.shopMoney?.amount,
        original_unit_price: item.node.originalUnitPriceSet?.shopMoney?.amount,
        original_line_price: item.node.originalTotalSet?.shopMoney?.amount,
      }));

      return {
        id: node.id,
        legacy_id: node.legacyResourceId,
        name: node.name,
        created_at: node.createdAt,
        updated_at: node.updatedAt,
        financial_status: node.displayFinancialStatus,
        fulfillment_status: node.displayFulfillmentStatus,
        tags: node.tags || [],
        note: node.note,
        total_price: node.totalPriceSet.shopMoney.amount,
        currency: node.totalPriceSet.shopMoney.currencyCode,
        customer: node.customer ? {
          id: node.customer.id,
          name: node.customer.displayName,
          email: node.customer.email,
          phone: node.customer.phone
        } : null,
        shipping_address: node.shippingAddress,
        metafields,
        line_items: lineItems,
      };
    });

    const response = {
      orders: transformedOrders,
      count: transformedOrders.length,
      pagination: shouldPaginate ? {
        total_fetched: transformedOrders.length,
        method: "full_pagination"
      } : {
        page_size: pageSize,
        has_more: false // Would need pageInfo from single query to determine
      }
    };

    console.log(`✅ Successfully fetched ${transformedOrders.length} orders`);
    res.json(response);

  } catch (error) {
    handleError(error, res, "Failed to fetch orders");
  }
});

/**
 * Individual order endpoint with comprehensive data
 */
app.get("/orders/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const legacyId = id.replace(/\D/g, ''); // Extract numeric ID
    
    console.log(`🔍 Fetching detailed order: ${legacyId}`);

    const orderQuery = `
      query GetOrder($id: ID!) {
        order(id: $id) {
          id
          legacyResourceId
          name
          createdAt
          updatedAt
          displayFinancialStatus
          displayFulfillmentStatus
          tags
          note
          email
          phone
          totalPriceSet {
            shopMoney {
              amount
              currencyCode
            }
          }
          customer {
            id
            displayName
            email
            phone
          }
          billingAddress {
            firstName
            lastName
            company
            address1
            address2
            city
            province
            country
            zip
            phone
          }
          shippingAddress {
            firstName
            lastName
            company
            address1
            address2
            city
            province
            country
            zip
            phone
          }
          lineItems(first: 50) {
            edges {
              node {
                title
                quantity
                sku
                variantTitle
                vendor
                originalUnitPriceSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                discountedUnitPriceSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                originalTotalSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                discountedTotalSet {
                  shopMoney {
                    amount
                    currencyCode
                  }
                }
                product {
                  title
                  productType
                  handle
                }
              }
            }
          }
          metafields(first: 50, namespace: "custom") {
            edges {
              node {
                id
                key
                value
                type
                namespace
              }
            }
          }
        }
      }
    `;

    const orderGID = `gid://shopify/Order/${legacyId}`;
    const data = await graphqlClient.query(orderQuery, { id: orderGID });
    
    if (!data.data.order) {
      return res.status(404).json({ error: "Order not found" });
    }

    const node = data.data.order;
    const metafields = {};
    node.metafields.edges.forEach((mf) => { 
      metafields[mf.node.key] = mf.node.value; 
    });

    const lineItems = node.lineItems.edges.map((item) => ({
      title: item.node.title,
      quantity: item.node.quantity,
      sku: item.node.sku,
      variantTitle: item.node.variantTitle,
      vendor: item.node.vendor,
      productTitle: item.node.product?.title,
      productType: item.node.product?.productType,
      productHandle: item.node.product?.handle,
      unit_price: item.node.discountedUnitPriceSet?.shopMoney?.amount || item.node.originalUnitPriceSet?.shopMoney?.amount,
      line_price: item.node.discountedTotalSet?.shopMoney?.amount || item.node.originalTotalSet?.shopMoney?.amount,
      original_unit_price: item.node.originalUnitPriceSet?.shopMoney?.amount,
      original_line_price: item.node.originalTotalSet?.shopMoney?.amount,
    }));

    // Fetch note_attributes via REST for compatibility
    let noteAttributes = {};
    try {
      const restOrder = await restClient.get(`/orders/${legacyId}.json`);
      restOrder.order.note_attributes.forEach((na) => {
        noteAttributes[na.name] = na.value;
      });
    } catch (restError) {
      console.warn("⚠️ Could not fetch note_attributes via REST:", restError.message);
    }

    const orderData = {
      id: node.id,
      legacy_id: node.legacyResourceId,
      name: node.name,
      created_at: node.createdAt,
      updated_at: node.updatedAt,
      financial_status: node.displayFinancialStatus,
      fulfillment_status: node.displayFulfillmentStatus,
      tags: node.tags || [],
      note: node.note,
      email: node.email,
      phone: node.phone,
      total_price: node.totalPriceSet.shopMoney.amount,
      currency: node.totalPriceSet.shopMoney.currencyCode,
      customer: node.customer ? {
        id: node.customer.id,
        name: node.customer.displayName,
        email: node.customer.email,
        phone: node.customer.phone
      } : null,
      billing_address: node.billingAddress,
      shipping_address: node.shippingAddress,
      metafields,
      attributes: noteAttributes,
      line_items: lineItems,
    };

    console.log(`✅ Successfully fetched order: ${node.name}`);
    res.json(orderData);

  } catch (error) {
    handleError(error, res, "Failed to fetch individual order");
  }
});

/**
 * REST fallback endpoints for legacy support
 */
app.get("/rest/orders/:id", async (req, res) => {
  try {
    const { id } = req.params;
    console.log(`🔄 REST fallback: fetching order ${id}`);
    
    const orderData = await restClient.get(`/orders/${id}.json`);
    res.json(orderData);
  } catch (error) {
    handleError(error, res, "REST order fetch failed");
  }
});

app.get("/rest/locations", async (req, res) => {
  try {
    console.log("🔄 REST: fetching locations");
    const locationsData = await restClient.get("/locations.json");
    res.json(locationsData);
  } catch (error) {
    handleError(error, res, "REST locations fetch failed");
  }
});

// Global error handler
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ 
        error: "File too large", 
        message: "Maximum file size is 25MB" 
      });
    }
  }
  
  handleError(err, res, "Unexpected server error");
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: "Endpoint not found",
    message: `${req.method} ${req.originalUrl} is not a valid endpoint`,
    availableEndpoints: [
      "GET /meta",
      "GET /orders", 
      "GET /orders/:id",
      "GET /rest/orders/:id",
      "GET /rest/locations",
      "GET /metafields",
      "POST /metafields",
      "POST /upload-file"
    ]
  });
});

// Start server
app.listen(PORT, () => {
  console.log("✅ ===============================================");
  console.log(`✅ Shopify Admin Proxy Server v2.0.0`);
  console.log(`✅ Running at: http://localhost:${PORT}`);
  console.log(`✅ Store: ${SHOPIFY_STORE_URL}`);
  console.log(`✅ API Version: ${SHOPIFY_API_VERSION}`);
  console.log(`✅ Environment: ${NODE_ENV}`);
  console.log("✅ ===============================================");
  console.log("🔗 Available endpoints:");
  console.log("   📊 GET  /meta              - Server & store info");
  console.log("   📋 GET  /orders            - Orders with pagination");
  console.log("   🔍 GET  /orders/:id        - Individual order");
  console.log("   🔄 GET  /rest/orders/:id   - REST fallback");
  console.log("   🏢 GET  /rest/locations    - Store locations");
  console.log("   📝 GET  /metafields        - Metafields help");
  console.log("   💾 POST /metafields        - Manage metafields");
  console.log("   📤 POST /upload-file       - File uploads");
  console.log("✅ ===============================================");
}); 
