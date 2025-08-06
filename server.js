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
  HUBSPOT_PRIVATE_APP_TOKEN,
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

if (!HUBSPOT_PRIVATE_APP_TOKEN) {
  console.warn("⚠️ HUBSPOT_PRIVATE_APP_TOKEN not set - HubSpot webhook functionality will be disabled");
}

// Security and performance configuration
const app = express();

// Trust proxy for proper rate limiting behind Render/CloudFlare
app.set('trust proxy', 1);

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
const allowedOrigins = [
  /\.myshopify\.com$/,
  /localhost:\d+$/,
  'https://www.exposurepack.com.au',
  'https://exposurepack.com.au',
  'http://www.exposurepack.com.au',
  'http://exposurepack.com.au',
  /\.exposurepack\.com\.au$/
];

const corsOptions = {
  origin: function (origin, callback) {
    console.log('🌐 CORS check for origin:', origin);
    console.log('🌐 NODE_ENV:', NODE_ENV);
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      console.log('✅ CORS: No origin header - allowing');
      return callback(null, true);
    }
    
    // In development, allow all origins
    if (NODE_ENV !== "production") {
      console.log('✅ CORS: Development mode - allowing all origins');
      return callback(null, true);
    }
    
    // TEMPORARY FIX: Allow exposurepack.com.au in production
    if (origin && origin.includes('exposurepack.com.au')) {
      console.log('✅ CORS: ExposurePack domain detected - allowing');
      return callback(null, true);
    }
    
    // Check against allowed origins
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (typeof allowedOrigin === 'string') {
        const matches = origin === allowedOrigin;
        console.log(`🔍 CORS: Checking string "${allowedOrigin}" against "${origin}": ${matches}`);
        return matches;
      } else if (allowedOrigin instanceof RegExp) {
        const matches = allowedOrigin.test(origin);
        console.log(`🔍 CORS: Checking regex ${allowedOrigin} against "${origin}": ${matches}`);
        return matches;
      }
      return false;
    });
    
    if (isAllowed) {
      console.log('✅ CORS: Origin allowed via allowed origins list');
      callback(null, true);
    } else {
      console.log('❌ CORS: Origin not allowed');
      console.log('📋 CORS: Allowed origins:', allowedOrigins);
      console.log('📋 CORS: Received origin:', origin);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'X-API-Key'],
  credentials: true,
  optionsSuccessStatus: 200 // For legacy browser support
};
app.use(cors(corsOptions));

// Additional CORS debugging - handle preflight requests manually if needed
app.options('*', (req, res) => {
  console.log('🔧 Manual OPTIONS preflight handler triggered');
  console.log('🔧 Origin:', req.headers.origin);
  console.log('🔧 Method:', req.headers['access-control-request-method']);
  console.log('🔧 Headers:', req.headers['access-control-request-headers']);
  
  // Set CORS headers manually for ExposurePack domain
  if (req.headers.origin && req.headers.origin.includes('exposurepack.com.au')) {
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key, X-API-Key');
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Max-Age', '86400'); // 24 hours
    console.log('✅ Manual CORS headers set for ExposurePack domain');
    return res.status(200).end();
  }
  
  console.log('⚠️ Manual OPTIONS handler - origin not recognized');
  res.status(204).end();
});

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
  // Bypass authentication for webhook endpoints and test endpoints
  if (req.path === '/webhook' || req.path === '/shopify-webhook' || req.path === '/fulfillments/test' || req.path === '/fulfillments/v2/test' || (req.path === '/fulfillments' && req.method === 'GET') || (req.path === '/fulfillments/v2' && req.method === 'GET')) {
    return next();
  }
  
  const apiKey = req.headers["x-api-key"];
  // Accept either the environment variable or the hardcoded key for backward compatibility
  const validKeys = [FRONTEND_SECRET, 'mypassword123'].filter(Boolean);
  if (!apiKey || !validKeys.includes(apiKey)) {
    console.log(`❌ Authentication failed. Received: "${apiKey}", Expected one of:`, validKeys);
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
 * HubSpot API client for deal and contact management
 */
class HubSpotClient {
  constructor() {
    if (!HUBSPOT_PRIVATE_APP_TOKEN) {
      throw new Error("HubSpot private app token is required");
    }
    
    this.baseURL = "https://api.hubapi.com";
    this.headers = {
      "Authorization": `Bearer ${HUBSPOT_PRIVATE_APP_TOKEN}`,
      "Content-Type": "application/json"
    };
  }

  async getDeal(dealId) {
    try {
      const response = await axios.get(
        `${this.baseURL}/crm/v3/objects/deals/${dealId}`,
        {
          headers: this.headers,
          params: {
            properties: [
              // Basic deal properties (restore working functionality)
              'dealname', 'amount', 'dealstage', 'closedate', 'hs_object_id',
              'notes_last_contacted', 'description', 'deal_currency_code',
              'hs_deal_stage_probability', 'hubspot_owner_id',
              // Add common HubSpot custom property patterns for addresses
              'shipping_address', 'billing_address', 'delivery_address',
              'ship_to_address', 'ship_to_street', 'ship_to_city', 'ship_to_state', 'ship_to_zip',
              'customer_address', 'customer_street', 'customer_city', 'customer_state', 'customer_zip',
              // Try common custom field naming patterns
              'address_line_1', 'address_line_2', 'street_address', 'delivery_street',
              'shipping_street', 'shipping_city', 'shipping_state', 'shipping_zip',
              'billing_street', 'billing_city', 'billing_state', 'billing_zip'
            ].join(','),
            associations: 'contacts,line_items'
          },
          timeout: 30000
        }
      );
      return response.data;
    } catch (error) {
      throw new Error(`Failed to fetch HubSpot deal ${dealId}: ${error.response?.data?.message || error.message}`);
    }
  }

  async getContact(contactId) {
    try {
      const response = await axios.get(
        `${this.baseURL}/crm/v3/objects/contacts/${contactId}`,
        {
          headers: this.headers,
          params: {
            properties: [
              // Basic contact info (restore working functionality)
              'firstname', 'lastname', 'email', 'phone', 'company',
              'address', 'city', 'state', 'zip', 'country',
              // Add common HubSpot custom address field patterns
              'street', 'address1', 'address2', 'street_address', 'mailing_address',
              'shipping_address', 'shipping_street', 'shipping_city', 'shipping_state', 'shipping_zip',
              'billing_address', 'billing_street', 'billing_city', 'billing_state', 'billing_zip',
              'delivery_address', 'delivery_street', 'delivery_city', 'delivery_state', 'delivery_zip',
              // Alternative common patterns
              'address_line_1', 'address_line_2', 'postal_code', 'postcode'
            ].join(',')
          },
          timeout: 30000
        }
      );
      return response.data;
    } catch (error) {
      throw new Error(`Failed to fetch HubSpot contact ${contactId}: ${error.response?.data?.message || error.message}`);
    }
  }

  async getDealInvoices(dealId) {
    try {
      console.log(`🔍 Fetching invoices for deal ${dealId}...`);
      // First, get invoices associated with the deal
      const response = await axios.get(
        `${this.baseURL}/crm/v3/objects/deals/${dealId}/associations/invoices`,
        {
          headers: this.headers,
          timeout: 30000
        }
      );
      
      console.log(`📊 Invoice association response:`, JSON.stringify(response.data, null, 2));
      
      if (!response.data.results || response.data.results.length === 0) {
        console.log(`ℹ️ No invoices found for deal ${dealId} - falling back to deal line items`);
        const fallbackItems = await this.getDealLineItems(dealId);
        return Array.isArray(fallbackItems) ? fallbackItems : [];
      }

      // Get the most recent invoice (or first one)
      const invoiceId = response.data.results[0].id;
      console.log(`📄 Processing invoice ID: ${invoiceId}`);
      
      // Fetch ALL invoice properties to see what's actually available
      const invoiceResponse = await axios.get(
        `${this.baseURL}/crm/v3/objects/invoices/${invoiceId}`,
        {
          headers: this.headers,
          params: {
            properties: [
              // Basic invoice properties (restore working functionality)
              'hs_createdate', 'hs_lastmodifieddate', 'hs_object_id',
              'hs_tax_amount', 'hs_subtotal_amount', 'hs_total_amount', 'hs_discount_amount',
              'hs_invoice_number', 'hs_status',
              // Add common invoice address field patterns
              'ship_to_address', 'ship_to_street', 'ship_to_city', 'ship_to_state', 'ship_to_zip',
              'bill_to_address', 'bill_to_street', 'bill_to_city', 'bill_to_state', 'bill_to_zip',
              'shipping_address', 'shipping_street', 'shipping_city', 'shipping_state', 'shipping_zip',
              'billing_address', 'billing_street', 'billing_city', 'billing_state', 'billing_zip',
              'delivery_address', 'delivery_street', 'delivery_city', 'delivery_state', 'delivery_zip',
              'customer_address', 'customer_street', 'customer_city', 'customer_state', 'customer_zip'
            ].join(','),
            associations: 'line_items'
          }
        }
      );
      
      console.log(`📄 Invoice details response:`, JSON.stringify(invoiceResponse.data, null, 2));

      const invoice = invoiceResponse.data;
      
      // Get invoice line items
      const lineItemsResponse = await axios.get(
        `${this.baseURL}/crm/v3/objects/invoices/${invoiceId}/associations/line_items`,
        {
          headers: this.headers,
          timeout: 30000
        }
      );

      if (!lineItemsResponse.data.results || lineItemsResponse.data.results.length === 0) {
        console.log(`ℹ️ No line items found for invoice ${invoiceId}`);
        return [];
      }

      // Fetch detailed line item data
      const lineItemPromises = lineItemsResponse.data.results.map(async (association) => {
        const lineItemResponse = await axios.get(
          `${this.baseURL}/crm/v3/objects/line_items/${association.id}`,
          {
            headers: this.headers,
            params: {
              properties: [
                'name',
                'quantity',
                'price',
                'amount',
                'hs_product_id',
                'description',
                'hs_sku'
              ].join(',')
            }
          }
        );
        return lineItemResponse.data;
      });

      const lineItems = await Promise.all(lineItemPromises);
      
      console.log(`✅ Found invoice ${invoice.properties.hs_invoice_number || invoiceId} with ${lineItems.length} line items`);
      console.log(`💰 Invoice totals - Subtotal: $${invoice.properties.hs_subtotal_amount || 'N/A'}, Tax: $${invoice.properties.hs_tax_amount || 'N/A'}, Total: $${invoice.properties.hs_total_amount || 'N/A'}`);
      console.log(`🔍 All invoice properties:`, Object.keys(invoice.properties || {}));
      console.log(`🔍 Tax-related properties:`, {
        hs_tax_amount: invoice.properties.hs_tax_amount,
        hs_subtotal_amount: invoice.properties.hs_subtotal_amount,
        hs_total_amount: invoice.properties.hs_total_amount
      });
      
      // Calculate totals from line items if not available on invoice
      let calculatedSubtotal = 0;
      let calculatedTax = 0;
      let calculatedTotal = 0;
      
      if (lineItems && lineItems.length > 0) {
        lineItems.forEach(item => {
          const props = item.properties;
          const amount = parseFloat(props.amount) || 0;
          calculatedSubtotal += amount;
        });
        
        // Assume 10% GST if we have subtotal but no tax info
        if (calculatedSubtotal > 0 && !invoice.properties.hs_tax_amount) {
          calculatedTax = calculatedSubtotal * 0.10;
        }
        
        calculatedTotal = calculatedSubtotal + calculatedTax;
      }
      
      console.log(`🧮 Calculated totals - Subtotal: $${calculatedSubtotal}, Tax: $${calculatedTax}, Total: $${calculatedTotal}`);
      
      // Use calculated values if invoice properties are missing
      const subtotal = parseFloat(invoice.properties.hs_subtotal_amount) || calculatedSubtotal;
      const tax = parseFloat(invoice.properties.hs_tax_amount) || calculatedTax;
      const total = parseFloat(invoice.properties.hs_total_amount) || calculatedTotal;
      
      // Return both line items and invoice totals
      return {
        lineItems: lineItems,
        invoice: {
          number: invoice.properties.hs_invoice_number || `INV-${invoiceId}`,
          subtotal: subtotal,
          tax: tax,
          discount: parseFloat(invoice.properties.hs_discount_amount) || 0,
          total: total,
          currency: invoice.properties.hs_currency || 'AUD'
        }
      };

    } catch (error) {
      console.warn(`⚠️ Failed to fetch invoice line items for deal ${dealId}:`, error.response?.data?.message || error.message);
      // Fallback to deal line items if invoice approach fails
      const fallbackItems = await this.getDealLineItems(dealId);
      return Array.isArray(fallbackItems) ? fallbackItems : [];
    }
  }

  async getDealLineItems(dealId) {
    try {
      const response = await axios.get(
        `${this.baseURL}/crm/v3/objects/deals/${dealId}/associations/line_items`,
        {
          headers: this.headers,
          timeout: 30000
        }
      );
      
      if (!response.data.results || response.data.results.length === 0) {
        return [];
      }

      // Fetch detailed line item data
      const lineItemPromises = response.data.results.map(async (association) => {
        const lineItemResponse = await axios.get(
          `${this.baseURL}/crm/v3/objects/line_items/${association.id}`,
          {
            headers: this.headers,
            params: {
              properties: [
                'name',
                'quantity',
                'price',
                'amount',
                'hs_product_id',
                'description',
                'hs_sku'
              ].join(',')
            }
          }
        );
        return lineItemResponse.data;
      });

      return await Promise.all(lineItemPromises);
    } catch (error) {
      console.warn(`⚠️ Failed to fetch deal line items for deal ${dealId}:`, error.response?.data?.message || error.message);
      return [];
    }
  }

  async getAssociatedContacts(dealId) {
    try {
      const response = await axios.get(
        `${this.baseURL}/crm/v3/objects/deals/${dealId}/associations/contacts`,
        {
          headers: this.headers,
          timeout: 30000
        }
      );
      
      if (!response.data.results || response.data.results.length === 0) {
        return [];
      }

      // Fetch detailed contact data for all associated contacts
      const contactPromises = response.data.results.map(association => 
        this.getContact(association.id)
      );

      return await Promise.all(contactPromises);
    } catch (error) {
      console.warn(`⚠️ Failed to fetch associated contacts for deal ${dealId}:`, error.response?.data?.message || error.message);
      return [];
    }
  }

  async createOrUpdateContact(contactData) {
    try {
      console.log(`👤 Creating/updating contact: ${contactData.email}`);
      
      // First, try to find existing contact by email
      try {
        const searchResponse = await axios.post(
          `${this.baseURL}/crm/v3/objects/contacts/search`,
          {
            filterGroups: [{
              filters: [{
                propertyName: 'email',
                operator: 'EQ',
                value: contactData.email
              }]
            }]
          },
          { headers: this.headers }
        );

        if (searchResponse.data.results && searchResponse.data.results.length > 0) {
          // Contact exists, update it
          const existingContact = searchResponse.data.results[0];
          console.log(`✅ Found existing contact: ${existingContact.id}`);
          
          const updateResponse = await axios.patch(
            `${this.baseURL}/crm/v3/objects/contacts/${existingContact.id}`,
            { properties: contactData },
            { headers: this.headers }
          );
          
          return updateResponse.data;
        }
      } catch (searchError) {
        console.log(`ℹ️ Contact search failed, will create new: ${searchError.message}`);
      }

      // Contact doesn't exist, create new one
      const createResponse = await axios.post(
        `${this.baseURL}/crm/v3/objects/contacts`,
        { properties: contactData },
        { headers: this.headers }
      );

      console.log(`✅ Created new contact: ${createResponse.data.id}`);
      return createResponse.data;

    } catch (error) {
      console.error(`❌ Failed to create/update contact:`, error.response?.data?.message || error.message);
      throw error;
    }
  }

  async createDeal(dealData) {
    try {
      console.log(`🤝 Creating deal: ${dealData.dealname}`);
      
      const response = await axios.post(
        `${this.baseURL}/crm/v3/objects/deals`,
        { properties: dealData },
        { headers: this.headers }
      );

      console.log(`✅ Created deal: ${response.data.id} - ${dealData.dealname}`);
      return response.data;

    } catch (error) {
      console.error(`❌ Failed to create deal:`, error.response?.data?.message || error.message);
      throw error;
    }
  }

  async associateContactWithDeal(contactId, dealId) {
    try {
      console.log(`🔗 Associating contact ${contactId} with deal ${dealId}`);
      
      const response = await axios.put(
        `${this.baseURL}/crm/v3/objects/deals/${dealId}/associations/contacts/${contactId}/280`,
        {},
        { headers: this.headers }
      );

      console.log(`✅ Associated contact with deal successfully`);
      return response.data;

    } catch (error) {
      console.warn(`⚠️ Failed to associate contact with deal:`, error.response?.data?.message || error.message);
      // Don't throw error - association failure shouldn't break the whole flow
    }
  }

  async createLineItem(lineItemData) {
    try {
      console.log(`📝 Creating line item: ${lineItemData.name}`);
      
      const response = await axios.post(
        `${this.baseURL}/crm/v3/objects/line_items`,
        { properties: lineItemData },
        { headers: this.headers }
      );

      console.log(`✅ Created line item: ${response.data.id} - ${lineItemData.name}`);
      return response.data;

    } catch (error) {
      console.error(`❌ Failed to create line item:`, error.response?.data?.message || error.message);
      throw error;
    }
  }

  async associateLineItemWithDeal(lineItemId, dealId) {
    try {
      console.log(`🔗 Associating line item ${lineItemId} with deal ${dealId}`);
      
      // Association type 20 is for line_items to deals
      const response = await axios.put(
        `${this.baseURL}/crm/v3/objects/line_items/${lineItemId}/associations/deals/${dealId}/20`,
        {},
        { headers: this.headers }
      );

      console.log(`✅ Associated line item with deal successfully`);
      return response.data;

    } catch (error) {
      console.warn(`⚠️ Failed to associate line item with deal:`, error.response?.data?.message || error.message);
      // Don't throw error - association failure shouldn't break the whole flow
    }
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

/**
 * Creates a HubSpot deal from Shopify order data
 */
async function createHubSpotDealFromShopifyOrder(order) {
  if (!HUBSPOT_PRIVATE_APP_TOKEN) {
    console.log("⚠️ HubSpot token not configured - cannot create deal");
    return;
  }

  console.log(`🔄 Creating HubSpot deal from Shopify order: ${order.name}`);

  try {
    // Extract customer information
    const customer = order.customer || {};
    const billingAddress = order.billing_address || {};
    const shippingAddress = order.shipping_address || {};

    // Prepare contact data
    const contactData = {
      email: customer.email || billingAddress.email || 'unknown@shopify.com',
      firstname: customer.first_name || billingAddress.first_name || '',
      lastname: customer.last_name || billingAddress.last_name || '',
      phone: customer.phone || billingAddress.phone || '',
      address: billingAddress.address1 || '',
      city: billingAddress.city || '',
      state: billingAddress.province || '',
      country: billingAddress.country || '',
      zip: billingAddress.zip || '',
      company: billingAddress.company || ''
    };

    // Create or update contact in HubSpot
    let contact;
    try {
      contact = await hubspotClient.createOrUpdateContact(contactData);
      console.log(`👤 Contact ready: ${contact.id} - ${contactData.email}`);
    } catch (contactError) {
      console.error(`❌ Failed to create contact, continuing without: ${contactError.message}`);
    }

    // Calculate deal amount
    const dealAmount = parseFloat(order.total_price) || 0;
    const currency = order.currency || 'AUD';

    // Prepare deal data
    const dealData = {
      dealname: `Shopify Order ${order.name}`,
      amount: dealAmount,
      dealstage: 'closedwon', // Set to closed won as requested
      pipeline: 'default', // You may need to adjust this based on your HubSpot setup
      closedate: new Date().toISOString().split('T')[0], // Today's date
      hubspot_owner_id: '', // You can set a default owner if needed
      
      // Custom properties for Shopify data
      shopify_order_id: order.id,
      shopify_order_number: order.name,
      shopify_order_status: order.financial_status,
      shopify_fulfillment_status: order.fulfillment_status || 'unfulfilled',
      
      // Additional info
      hs_deal_currency_code: currency,
      deal_source: 'Shopify',
      deal_description: `Order imported from Shopify\nOrder #: ${order.name}\nItems: ${order.line_items?.length || 0}\nCustomer: ${customer.email || 'N/A'}${order.line_items?.length > 0 ? `\n\nLine Items:\n${order.line_items.map((item, i) => `${i + 1}. ${item.title} (Qty: ${item.quantity}, $${parseFloat(item.price).toFixed(2)})`).join('\n')}` : ''}`
    };

    console.log(`🤝 Creating deal: ${dealData.dealname} - $${dealAmount} ${currency}`);
    console.log(`📊 Deal summary: ${order.line_items?.length || 0} line items, Total: $${dealAmount}`);
    if (order.line_items && order.line_items.length > 0) {
      console.log(`📝 Line items preview:`);
      order.line_items.forEach((item, i) => {
        console.log(`   ${i + 1}. ${item.title} (Qty: ${item.quantity}, $${parseFloat(item.price).toFixed(2)})`);
      });
    }

    // Create deal in HubSpot
    const deal = await hubspotClient.createDeal(dealData);
    console.log(`✅ Created HubSpot deal: ${deal.id} - ${dealData.dealname}`);

    // Associate contact with deal if both exist
    if (contact && deal) {
      await hubspotClient.associateContactWithDeal(contact.id, deal.id);
    }

    // Create line items in HubSpot if order has line items
    if (order.line_items && order.line_items.length > 0) {
      console.log(`📝 Creating ${order.line_items.length} line items in HubSpot for deal ${deal.id}`);
      
      try {
        for (let i = 0; i < order.line_items.length; i++) {
          const shopifyLineItem = order.line_items[i];
          
          // Transform Shopify line item to HubSpot format
          const hubspotLineItem = {
            name: shopifyLineItem.title || shopifyLineItem.name || `Item ${i + 1}`,
            quantity: parseInt(shopifyLineItem.quantity) || 1,
            price: parseFloat(shopifyLineItem.price) || 0,
            amount: parseFloat(shopifyLineItem.price) * (parseInt(shopifyLineItem.quantity) || 1),
            hs_sku: shopifyLineItem.sku || shopifyLineItem.variant_id || `SHOPIFY-${shopifyLineItem.id}`,
            description: `Shopify Line Item\nVariant ID: ${shopifyLineItem.variant_id || 'N/A'}\nProduct ID: ${shopifyLineItem.product_id || 'N/A'}${shopifyLineItem.variant_title ? `\nVariant: ${shopifyLineItem.variant_title}` : ''}`,
            // Custom properties for Shopify data
            shopify_line_item_id: shopifyLineItem.id,
            shopify_product_id: shopifyLineItem.product_id,
            shopify_variant_id: shopifyLineItem.variant_id
          };

          console.log(`📝 Creating line item: ${hubspotLineItem.name} (Qty: ${hubspotLineItem.quantity}, Price: $${hubspotLineItem.price})`);

          // Create line item in HubSpot
          const createdLineItem = await hubspotClient.createLineItem(hubspotLineItem);
          
          // Associate line item with deal
          if (createdLineItem && createdLineItem.id) {
            await hubspotClient.associateLineItemWithDeal(createdLineItem.id, deal.id);
          }
        }
        
        console.log(`✅ Successfully created all ${order.line_items.length} line items in HubSpot`);
        
      } catch (lineItemError) {
        console.error(`❌ Error creating line items (continuing with deal creation):`, lineItemError.message);
        // Don't throw error - line item creation failure shouldn't break the whole flow
      }
    } else {
      console.log(`ℹ️ No line items found in Shopify order ${order.name}`);
    }

    console.log(`✅ Successfully created HubSpot deal from Shopify order ${order.name}`);
    return deal;

  } catch (error) {
    console.error(`❌ Error creating HubSpot deal from Shopify order:`, error.message);
    console.error(`❌ Stack trace:`, error.stack);
    throw error;
  }
}

/**
 * Creates a Shopify order from HubSpot deal data
 */
async function createShopifyOrderFromHubspotInvoice(dealId) {
  if (!HUBSPOT_PRIVATE_APP_TOKEN) {
    throw new Error("HubSpot integration not configured - missing HUBSPOT_PRIVATE_APP_TOKEN");
  }

  console.log(`🔄 Creating Shopify order from HubSpot deal: ${dealId}`);

  try {
    // Fetch deal details from HubSpot
    const deal = await hubspotClient.getDeal(dealId);
    const contacts = await hubspotClient.getAssociatedContacts(dealId);
    
    // Debug: Check all associations for this deal
    try {
      const allAssociationsResponse = await axios.get(
        `https://api.hubapi.com/crm/v3/objects/deals/${dealId}`,
        {
          headers: { 'Authorization': `Bearer ${HUBSPOT_PRIVATE_APP_TOKEN}` },
          params: {
            associations: ['contacts', 'line_items', 'invoices', 'quotes'],
            properties: 'dealname,amount'
          }
        }
      );
      console.log(`🔗 All deal associations:`, JSON.stringify(allAssociationsResponse.data.associations || {}, null, 2));
    } catch (error) {
      console.log(`⚠️ Could not fetch deal associations:`, error.response?.data?.message || error.message);
    }
    
    const invoiceData = await hubspotClient.getDealInvoices(dealId);

    console.log(`📋 Deal: ${deal.properties.dealname || 'Unnamed Deal'} - $${deal.properties.amount || '0'}`);
    console.log(`👥 Associated contacts: ${contacts.length}`);
    
    // Handle both old format (array) and new format (object with lineItems and invoice)
    let invoiceLineItems = [];
    let invoiceInfo = null;
    
    if (Array.isArray(invoiceData)) {
      // Old format - just line items
      invoiceLineItems = invoiceData;
      console.log(`🧾 Invoice line items: ${invoiceLineItems.length}`);
    } else if (invoiceData && invoiceData.lineItems) {
      // New format - line items with invoice totals
      invoiceLineItems = invoiceData.lineItems;
      invoiceInfo = invoiceData.invoice;
      console.log(`🧾 Invoice line items: ${invoiceLineItems.length}`);
      console.log(`💰 Invoice info: ${invoiceInfo.number} - Subtotal: $${invoiceInfo.subtotal}, Tax: $${invoiceInfo.tax}, Total: $${invoiceInfo.total}`);
    } else {
      console.log(`🧾 No invoice data found`);
    }

    // Get primary contact (first one)
    const primaryContact = contacts[0];
    if (!primaryContact) {
      throw new Error("No associated contact found for deal");
    }

    const contactProps = primaryContact.properties;
    console.log(`👤 Primary contact: ${contactProps.email || 'No email'}`);

    // Transform invoice line items for Shopify
    // Use total amount as price with quantity 1 to avoid decimal rounding issues
    const shopifyLineItems = invoiceLineItems.map(item => {
      const props = item.properties;
      const originalQuantity = parseInt(props.quantity) || 1;
      const unitPrice = parseFloat(props.price) || 0;
      // Fix: Only use fallback calculation if amount is not a valid number (including 0)
      const parsedAmount = parseFloat(props.amount);
      const totalAmount = !isNaN(parsedAmount) ? parsedAmount : (unitPrice * originalQuantity) || 0;
      
      const transformedItem = {
        title: `${props.name || 'HubSpot Invoice Item'}${originalQuantity > 1 ? ` (${originalQuantity.toLocaleString()} units)` : ''}`,
        quantity: 1, // Always 1 to use total amount directly
        price: totalAmount.toFixed(2), // Use total amount to avoid rounding issues
        sku: props.hs_sku || `INVOICE-${item.id}`,
        vendor: 'HubSpot Invoice',
        requires_shipping: true,
        taxable: true,
        fulfillment_service: 'manual'
      };
      
      console.log(`🔄 Transformed: "${props.name}" | HubSpot: ${originalQuantity} × $${unitPrice} = $${totalAmount} | Shopify: 1 × $${totalAmount.toFixed(2)}`);
      return transformedItem;
    });

    // If no invoice line items, create a placeholder item
    if (shopifyLineItems.length === 0) {
      shopifyLineItems.push({
        title: deal.properties.dealname || 'HubSpot Deal',
        quantity: 1,
        price: parseFloat(deal.properties.amount) || '0.00',
        sku: `DEAL-${dealId}`,
        vendor: 'HubSpot Import',
        requires_shipping: true,
        taxable: true,
        fulfillment_service: 'manual'
      });
    }

    // Build customer data with validation fixes
    const firstName = contactProps.firstname || 'Customer';
    const lastName = contactProps.lastname || 'Name'; // Fix: Shopify requires last name
    const rawPhone = contactProps.phone || '';
    
    // Fix: Format phone number for Australian format (Shopify validation)
    let formattedPhone = null;
    if (rawPhone) {
      // Remove all non-digit characters
      const digitsOnly = rawPhone.replace(/\D/g, '');
      
      // Convert to Australian international format (+61...)
      if (digitsOnly.startsWith('0') && digitsOnly.length === 10) {
        // Australian mobile: 0432293345 -> +61432293345
        formattedPhone = `+61${digitsOnly.slice(1)}`;
      } else if (digitsOnly.length === 9) {
        // Missing leading 0: 432293345 -> +61432293345
        formattedPhone = `+61${digitsOnly}`;
      } else if (digitsOnly.startsWith('61') && digitsOnly.length === 11) {
        // Already in AU format without +: 61432293345 -> +61432293345
        formattedPhone = `+${digitsOnly}`;
      } else if (digitsOnly.startsWith('614') && digitsOnly.length === 12) {
        // Already in full AU format: 61432293345 -> +61432293345
        formattedPhone = `+${digitsOnly}`;
      } else {
        // Keep original if we can't parse it, but add + if it looks international
        formattedPhone = digitsOnly.length >= 10 ? `+${digitsOnly}` : rawPhone;
      }
    }

    // Determine company name for customer record
    const companyName = contactProps.company || 
                       deal.properties.dealname?.split(' - ')[0] || // Extract from deal name
                       'HubSpot Customer';

    const customer = {
      first_name: firstName,
      last_name: lastName,
      email: contactProps.email || `hubspot-${dealId}@placeholder.com`,
      phone: formattedPhone,
      // Note: Shopify customer object doesn't have company field, 
      // but we'll ensure it's in shipping/billing addresses
    };

    // Extract address information from multiple sources
    console.log(`🏠 Extracting address information...`);
    console.log(`📋 Deal properties:`, deal.properties);
    console.log(`🔍 Deal properties with address info:`, 
      Object.keys(deal.properties).filter(key => 
        key.toLowerCase().includes('address') || 
        key.toLowerCase().includes('street') ||
        key.toLowerCase().includes('city') ||
        key.toLowerCase().includes('state') ||
        key.toLowerCase().includes('zip') ||
        key.toLowerCase().includes('ship') ||
        key.toLowerCase().includes('bill') ||
        key.toLowerCase().includes('delivery')
      )
    );
    console.log(`📋 Contact properties:`, contactProps);
    console.log(`🔍 Contact properties with address info:`, 
      Object.keys(contactProps).filter(key => 
        key.toLowerCase().includes('address') || 
        key.toLowerCase().includes('street') ||
        key.toLowerCase().includes('city') ||
        key.toLowerCase().includes('state') ||
        key.toLowerCase().includes('zip') ||
        key.toLowerCase().includes('country')
      )
    );
    console.log(`📋 Invoice info:`, invoiceInfo);
    
    // Debug: Log all available invoice properties to see what address fields exist
    if (invoiceInfo && invoiceInfo.properties) {
      console.log(`🔍 All invoice properties available:`, Object.keys(invoiceInfo.properties));
      console.log(`🔍 Invoice properties with 'address' in name:`, 
        Object.keys(invoiceInfo.properties).filter(key => 
          key.toLowerCase().includes('address') || 
          key.toLowerCase().includes('street') ||
          key.toLowerCase().includes('city') ||
          key.toLowerCase().includes('state') ||
          key.toLowerCase().includes('zip') ||
          key.toLowerCase().includes('ship') ||
          key.toLowerCase().includes('bill')
        )
      );
      console.log(`🔍 Full invoice properties object:`, JSON.stringify(invoiceInfo.properties, null, 2));
    }
    
    // Helper function to extract address from deal properties
    const getDealAddress = (type = 'shipping') => {
      const props = deal.properties;
      console.log(`🏢 Looking for ${type} address in deal properties:`, Object.keys(props));
      
      // Common deal address field patterns
      const addressFields = {
        billing: {
          address1: props.billing_address || props.billing_street || props.bill_to_address || props.bill_to_street || '',
          city: props.billing_city || props.bill_to_city || '',
          province: props.billing_state || props.billing_province || props.bill_to_state || '',
          country: props.billing_country || props.bill_to_country || 'Australia',
          zip: props.billing_zip || props.billing_postal_code || props.bill_to_zip || '',
          company: props.billing_company || props.bill_to_company || contactProps.company || ''
        },
        shipping: {
          address1: props.shipping_address || props.shipping_street || props.ship_to_address || props.ship_to_street ||
                   props.delivery_address || props.delivery_street || props.customer_address || props.customer_street || '',
          city: props.shipping_city || props.ship_to_city || props.delivery_city || props.customer_city || '',
          province: props.shipping_state || props.shipping_province || props.ship_to_state || 
                   props.delivery_state || props.customer_state || '',
          country: props.shipping_country || props.ship_to_country || props.delivery_country || 
                  props.customer_country || 'Australia',
          zip: props.shipping_zip || props.shipping_postal_code || props.ship_to_zip || 
              props.delivery_zip || props.customer_zip || '',
          company: props.shipping_company || props.ship_to_company || props.delivery_company || 
                  props.customer_company || contactProps.company || ''
        }
      };
      
      const addressData = addressFields[type];
      
      // Only return if we have at least address1 or city
      if (addressData.address1 || addressData.city) {
        console.log(`🏢 Found ${type} address in deal:`, addressData);
        return {
          first_name: firstName,
          last_name: lastName,
          company: addressData.company,
          address1: addressData.address1,
          city: addressData.city,
          province: addressData.province,
          country: addressData.country,
          zip: addressData.zip,
          phone: formattedPhone
        };
      }
      
      return null;
    };

    // Helper function to extract address from contact properties
          const getContactAddress = () => {
        // Try multiple field name variations that HubSpot uses
        const address1 = contactProps.address || contactProps.street || contactProps.address1 || 
                         contactProps.street_address || contactProps.mailing_address || 
                         contactProps.billing_address || contactProps.shipping_address || '';
        
        const city = contactProps.city || contactProps.mailing_city || 
                     contactProps.billing_city || contactProps.shipping_city || '';
        
        const state = contactProps.state || contactProps.province || contactProps.region ||
                      contactProps.mailing_state || contactProps.billing_state || 
                      contactProps.shipping_state || '';
        
        const country = contactProps.country || contactProps.mailing_country ||
                        contactProps.billing_country || contactProps.shipping_country || 'Australia';
        
        const zip = contactProps.zip || contactProps.postal_code || contactProps.postcode ||
                    contactProps.zipcode || contactProps.mailing_zip || 
                    contactProps.billing_zip || contactProps.shipping_zip || '';
        
        console.log(`👤 Contact address extraction - address1: "${address1}", city: "${city}", state: "${state}", zip: "${zip}"`);
        
        return {
          first_name: firstName,
          last_name: lastName,
          company: companyName, // Use determined company name
          address1: address1,
          city: city,
          province: state,
          country: country,
          zip: zip,
          phone: formattedPhone
        };
      };
    
    // Helper function to extract address from invoice if available
    const getInvoiceAddress = (type = 'shipping') => {
      if (!invoiceInfo || !invoiceInfo.properties) return null;
      
      const props = invoiceInfo.properties;
      console.log(`🏠 Looking for ${type} address in invoice properties:`, Object.keys(props));
      
      // Common HubSpot invoice address field patterns
      const addressFields = {
        billing: {
          address1: props.billing_address || props.billing_street || props.bill_to_address1 || '',
          city: props.billing_city || props.bill_to_city || '',
          province: props.billing_state || props.billing_province || props.bill_to_state || '',
          country: props.billing_country || props.bill_to_country || 'Australia',
          zip: props.billing_zip || props.billing_postal_code || props.bill_to_zip || '',
          company: props.billing_company || props.bill_to_company || contactProps.company || ''
        },
        shipping: {
          address1: props.shipping_address || props.shipping_street || props.ship_to_address1 || props.ship_to_street || '',
          city: props.shipping_city || props.ship_to_city || '',
          province: props.shipping_state || props.shipping_province || props.ship_to_state || '',
          country: props.shipping_country || props.ship_to_country || 'Australia',
          zip: props.shipping_zip || props.shipping_postal_code || props.ship_to_zip || '',
          company: props.shipping_company || props.ship_to_company || contactProps.company || ''
        }
      };
      
      const addressData = addressFields[type];
      
      // Only return if we have at least address1 or city
      if (addressData.address1 || addressData.city) {
        return {
          first_name: firstName,
          last_name: lastName,
          company: addressData.company,
          address1: addressData.address1,
          city: addressData.city,
          province: addressData.province,
          country: addressData.country,
          zip: addressData.zip,
          phone: formattedPhone
        };
      }
      
      return null;
    };
    
    // Try to get specific addresses from all sources, with fallbacks
    const dealShippingAddress = getDealAddress('shipping');
    const dealBillingAddress = getDealAddress('billing');
    const invoiceShippingAddress = getInvoiceAddress('shipping');
    const invoiceBillingAddress = getInvoiceAddress('billing');
    const contactAddress = getContactAddress();
    
    console.log(`🏠 Address extraction results:`);
    console.log(`   🏢 Deal shipping:`, dealShippingAddress);
    console.log(`   🏢 Deal billing:`, dealBillingAddress);
    console.log(`   📦 Invoice shipping:`, invoiceShippingAddress);
    console.log(`   💰 Invoice billing:`, invoiceBillingAddress);
    console.log(`   👤 Contact address:`, contactAddress);
    
    // Build final addresses with proper fallback logic
    // Priority: Deal address → Invoice address → Contact address → Manual entry
    // IMPORTANT: If shipping isn't available, fall back to billing address
    let shippingAddress = dealShippingAddress || invoiceShippingAddress || dealBillingAddress || 
                         invoiceBillingAddress || contactAddress;
    let billingAddress = dealBillingAddress || invoiceBillingAddress || contactAddress;
    
    // If we still don't have addresses, ensure both billing and shipping use the same contact address
    if (!shippingAddress && !billingAddress && contactAddress) {
      console.log(`⚠️ No specific address data found, using contact address for both shipping and billing`);
      shippingAddress = contactAddress;
      billingAddress = contactAddress;
    }
    
    // Final validation - ensure we have addresses
    if (!shippingAddress || !billingAddress) {
      console.log(`🚨 WARNING: Missing address data after all fallbacks`);
      console.log(`   📦 Shipping address: ${!!shippingAddress}`);
      console.log(`   💰 Billing address: ${!!billingAddress}`);
    }
    
    // Manual address database for known customers (temporary solution)
    // TODO: Remove this when HubSpot properly stores address data
    const knownAddresses = {
      // Deal ID based addresses
      '40546879900': {
        company: 'The hoi polloi',
        address1: '234-226 flinders street',
        city: 'Townsville',
        province: 'QLD',
        zip: '4812'
      },
      // Email based addresses
      'admin@thehoi.com.au': {
        company: 'The hoi polloi', 
        address1: '234-226 flinders street',
        city: 'Townsville',
        province: 'QLD',
        zip: '4812'
      },
      'info@alfabakehouse.com.au': {
        company: 'Alfa Bakehouse',
        address1: 'TBC - Contact customer for address',
        city: 'TBC',
        province: 'TBC', 
        zip: 'TBC'
      }
    };
    
    // Try to find address by deal ID or email
    const dealKey = dealId.toString();
    const emailKey = contactProps.email?.toLowerCase();
    let knownAddress = knownAddresses[dealKey] || knownAddresses[emailKey];
    
    if (knownAddress) {
      console.log(`🔧 Applying manual address override for ${dealKey} / ${emailKey}`);
      const manualAddress = {
        first_name: firstName,
        last_name: lastName,
                   company: knownAddress.company || companyName,
        address1: knownAddress.address1,
        city: knownAddress.city,
        province: knownAddress.province,
        country: 'Australia',
        zip: knownAddress.zip,
        phone: formattedPhone
      };
      shippingAddress = manualAddress;
      billingAddress = manualAddress;
      console.log(`🔧 Manual address applied:`, manualAddress);
    } else {
      console.log(`⚠️ No manual address found for deal ${dealKey} or email ${emailKey}`);
      console.log(`📝 Consider adding address manually to knownAddresses database`);
    }
    
    // Log address source information for debugging
    const getAddressSource = (address, isShipping = false) => {
      if (address === dealShippingAddress) return 'Deal Shipping';
      if (address === dealBillingAddress) return isShipping ? 'Deal Billing (fallback)' : 'Deal Billing';  
      if (address === invoiceShippingAddress) return 'Invoice Shipping';
      if (address === invoiceBillingAddress) return isShipping ? 'Invoice Billing (fallback)' : 'Invoice Billing';
      if (address === contactAddress) return 'Contact';
      return 'Manual Override';
    };
    
    console.log(`🏠 Final addresses:`);
    console.log(`   📦 Shipping: ${getAddressSource(shippingAddress, true)} ->`, shippingAddress);
    console.log(`   💰 Billing: ${getAddressSource(billingAddress, false)} ->`, billingAddress);

    // Create order via Shopify REST API
    const orderData = {
      order: {
        line_items: shopifyLineItems,
        customer: customer,
        billing_address: billingAddress,
        shipping_address: shippingAddress,
        financial_status: 'paid', // Mark as paid by default as requested
        tags: ['hubspot-import', `hubspot-deal-${dealId}`],
        note: `Imported from HubSpot Deal: ${deal.properties.dealname || dealId}\nDeal ID: ${dealId}\nOriginal Amount: $${deal.properties.amount || '0'}${invoiceInfo ? `\nInvoice: ${invoiceInfo.number}` : ''}`,
        note_attributes: [
          { name: 'hubspot_deal_id', value: dealId },
          { name: 'hubspot_deal_name', value: deal.properties.dealname || '' },
          { name: 'import_source', value: 'hubspot_webhook' },
          { name: 'import_date', value: new Date().toISOString() },
          ...(invoiceInfo ? [{ name: 'hubspot_invoice_number', value: invoiceInfo.number }] : [])
        ],
        send_receipt: false, // Don't send automatic receipt
        send_fulfillment_receipt: false,
        inventory_behaviour: 'decrement_obeying_policy',
        // Add tax lines if we have invoice tax information
        ...(invoiceInfo && invoiceInfo.tax > 0 ? {
          tax_lines: [{
            title: 'GST',
            price: invoiceInfo.tax.toFixed(2),
            rate: (invoiceInfo.subtotal > 0 ? (invoiceInfo.tax / invoiceInfo.subtotal) : 0.10),
            price_set: {
              shop_money: {
                amount: invoiceInfo.tax.toFixed(2),
                currency_code: invoiceInfo.currency || 'AUD'
              },
              presentment_money: {
                amount: invoiceInfo.tax.toFixed(2),
                currency_code: invoiceInfo.currency || 'AUD'
              }
            }
          }],
          total_tax: invoiceInfo.tax.toFixed(2)
        } : {}),
        // Add discount lines if we have invoice discount information
        ...(invoiceInfo && invoiceInfo.discount > 0 ? {
          discount_codes: [{
            code: 'HUBSPOT_DISCOUNT',
            amount: invoiceInfo.discount.toFixed(2),
            type: 'fixed_amount'
          }]
        } : {})
      }
    };

    console.log(`🛒 Creating Shopify order with ${shopifyLineItems.length} line items from HubSpot invoice`);
    
    // Debug tax information
    if (invoiceInfo && invoiceInfo.tax > 0) {
      console.log(`💰 Adding tax to Shopify order: $${invoiceInfo.tax} (${((invoiceInfo.tax / invoiceInfo.subtotal) * 100).toFixed(1)}%)`);
      console.log(`💰 Order data tax_lines:`, JSON.stringify(orderData.order.tax_lines, null, 2));
    } else {
      console.log(`⚠️ No tax information found in invoice data`);
    }

    // Log the complete order data being sent to Shopify for debugging
    console.log(`🔍 Complete Shopify order payload:`, JSON.stringify(orderData, null, 2));

    let createdOrder;
    try {
      // Create the order using REST API
      const response = await restClient.post('/orders.json', orderData);
      createdOrder = response.order;
    } catch (shopifyError) {
      console.error(`❌ Shopify order creation failed:`, shopifyError.message);
      
      if (shopifyError.response) {
        console.error(`📊 Shopify Error Status:`, shopifyError.response.status);
        console.error(`📋 Shopify Error Headers:`, shopifyError.response.headers);
        console.error(`📄 Shopify Error Body:`, shopifyError.response.body || shopifyError.response.data);
        
        // Try to extract specific validation errors
        const errorBody = shopifyError.response.body || shopifyError.response.data;
        if (errorBody && errorBody.errors) {
          console.error(`🚨 Specific Shopify validation errors:`);
          if (typeof errorBody.errors === 'object') {
            Object.entries(errorBody.errors).forEach(([field, messages]) => {
              console.error(`   - ${field}: ${Array.isArray(messages) ? messages.join(', ') : messages}`);
            });
          } else {
            console.error(`   - ${errorBody.errors}`);
          }
        }
      }
      
      throw shopifyError;
    }

    console.log(`✅ Successfully created Shopify order: ${createdOrder.name} (ID: ${createdOrder.id})`);

    // Add additional metafields for tracking (with safety checks for blank values)
    const orderGID = `gid://shopify/Order/${createdOrder.id}`;
    
    // Only set metafields if we have valid values
    if (dealId) {
      await metafieldManager.setMetafield(
        orderGID,
        'hubspot',
        'deal_id',
        dealId.toString(),
        'single_line_text_field'
      );
    }

    const dealName = deal.properties.dealname || deal.properties.deal_name || `Deal ${dealId}`;
    if (dealName && dealName.trim() !== '') {
      await metafieldManager.setMetafield(
        orderGID,
        'hubspot',
        'deal_name',
        dealName.trim(),
        'single_line_text_field'
      );
    }

    const dealAmount = deal.properties.amount || deal.properties.deal_amount || '0';
    if (dealAmount && dealAmount !== '') {
      await metafieldManager.setMetafield(
        orderGID,
        'hubspot',
        'original_amount',
        dealAmount.toString(),
        'number_decimal'
      );
    }

    console.log(`📝 Added HubSpot tracking metafields to order ${createdOrder.name}`);

    return {
      success: true,
      order: {
        id: createdOrder.id,
        name: createdOrder.name,
        total_price: createdOrder.total_price,
        financial_status: createdOrder.financial_status,
        hubspot_deal_id: dealId
      }
    };

  } catch (error) {
    console.error(`❌ Failed to create Shopify order from HubSpot deal ${dealId}:`, error.message);
    throw error;
  }
}

// ===========================================
// INITIALIZE CLIENTS
// ===========================================

const graphqlClient = new ShopifyGraphQLClient();
const restClient = new ShopifyRESTClient();
const metafieldManager = new MetafieldManager(graphqlClient);
const fileUploadManager = new FileUploadManager(graphqlClient);

// Initialize HubSpot client only if token is available
let hubspotClient = null;
if (HUBSPOT_PRIVATE_APP_TOKEN) {
  try {
    hubspotClient = new HubSpotClient();
    console.log("✅ HubSpot client initialized successfully");
  } catch (error) {
    console.error("❌ Failed to initialize HubSpot client:", error.message);
  }
} else {
  console.log("ℹ️ HubSpot client not initialized - token not provided");
}

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
      hubspot: {
        enabled: !!hubspotClient,
        webhookEndpoint: "/webhook"
      },
      endpoints: {
        graphql: ["/orders", "/orders/:id"],
        rest: ["/rest/orders/:id", "/rest/locations"],
        metafields: ["/metafields"],
        files: ["/upload-file"],
        webhooks: ["/webhook"],
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
 * Test endpoint to verify server connectivity
 */
app.get("/fulfillments/test", (req, res) => {
  console.log("🧪 Test endpoint hit");
  res.json({ 
    message: "Fulfillment endpoint is reachable",
    timestamp: new Date().toISOString(),
    server: "shopify-admin-proxy"
  });
});

/**
 * Debug endpoint to check if fulfillments path works
 */
app.get("/fulfillments", (req, res) => {
  console.log("🧪 GET /fulfillments hit (should be POST)");
  res.json({ 
    error: "Method not allowed",
    message: "This endpoint only accepts POST requests",
    expected: "POST /fulfillments",
    timestamp: new Date().toISOString()
  });
});

/**
 * Fulfillment endpoint - Creates Shopify fulfillments with tracking info
 */
app.post("/fulfillments", authenticate, async (req, res) => {
  // Ensure JSON response
  res.setHeader('Content-Type', 'application/json');
  
  try {
    console.log("📦 ===============================================");
    console.log("📦 FULFILLMENT ENDPOINT HIT");
    console.log("📦 ===============================================");
    console.log("📋 Request headers:", req.headers);
    console.log("📋 Request body:", req.body);
    console.log("📦 ===============================================");

    const { orderId, fulfillmentData } = req.body;

    if (!orderId || !fulfillmentData) {
      console.log("❌ Missing required data - orderId or fulfillmentData");
      return res.status(400).json({
        error: "Missing required data",
        message: "orderId and fulfillmentData are required"
      });
    }

    console.log(`📦 Creating fulfillment for order: ${orderId}`);
    console.log(`📋 Fulfillment data:`, JSON.stringify(fulfillmentData, null, 2));

    // Validate orderId format
    if (!orderId.startsWith('gid://shopify/Order/')) {
      return res.status(400).json({
        error: "Invalid orderId format",
        message: "orderId must be in format: gid://shopify/Order/ORDER_ID"
      });
    }

    // Extract numeric order ID for REST API
    const numericOrderId = orderId.replace('gid://shopify/Order/', '');
    
    // First, fetch the order to check its status
    console.log(`🔍 Fetching order details first to check fulfillability...`);
    try {
      const orderResponse = await restClient.get(`/orders/${numericOrderId}.json`);
      const order = orderResponse.order;
      
      console.log(`📋 Order Status Check:`);
      console.log(`   💰 Financial Status: ${order.financial_status}`);
      console.log(`   📦 Fulfillment Status: ${order.fulfillment_status}`);
      console.log(`   🏷️ Tags: ${order.tags}`);
      console.log(`   📅 Created: ${order.created_at}`);
      console.log(`   📝 Line Items: ${order.line_items?.length || 0}`);
      
      // Check if order is fulfillable
      if (order.financial_status?.toLowerCase() !== 'paid') {
        return res.status(400).json({
          error: "Order not fulfillable",
          message: `Order must be paid before fulfillment. Current status: ${order.financial_status}`,
          timestamp: new Date().toISOString()
        });
      }
      
      if (order.fulfillment_status?.toLowerCase() === 'fulfilled') {
        return res.status(400).json({
          error: "Order not fulfillable", 
          message: "Order is already fully fulfilled",
          timestamp: new Date().toISOString()
        });
      }
      
      console.log(`✅ Order appears fulfillable, proceeding with fulfillment creation...`);
      
    } catch (orderFetchError) {
      console.error(`⚠️ Could not fetch order details for pre-check:`, orderFetchError.message);
      console.log(`🔄 Proceeding with fulfillment anyway...`);
    }

    // Get the first available location if not specified
    if (!fulfillmentData.fulfillment.location_id || fulfillmentData.fulfillment.location_id === null) {
      try {
        console.log(`🏪 Getting store locations to set location_id...`);
        const locationsResponse = await restClient.get('/locations.json');
        const locations = locationsResponse.locations || [];
        
        if (locations.length > 0) {
          fulfillmentData.fulfillment.location_id = locations[0].id;
          console.log(`📍 Using location_id: ${fulfillmentData.fulfillment.location_id} (${locations[0].name || 'Default'})`);
        } else {
          console.log(`⚠️ No locations found, proceeding without location_id`);
          delete fulfillmentData.fulfillment.location_id;
        }
      } catch (locationError) {
        console.error(`⚠️ Could not fetch locations:`, locationError.message);
        console.log(`🔄 Proceeding without location_id...`);
        delete fulfillmentData.fulfillment.location_id;
      }
    }

    // Add improved line item handling - fulfill entire order if no specific line items
    console.log(`📋 Creating fulfillment for entire order (no line item restrictions)`);
    // Don't specify line_items to fulfill the entire order

    console.log(`🔍 Making Shopify REST API call:`);
    console.log(`📍 URL: /orders/${numericOrderId}/fulfillments.json`);
    console.log(`🔐 Using API version: ${SHOPIFY_API_VERSION}`);
    console.log(`🏪 Store: ${SHOPIFY_STORE_URL}`);
    console.log(`📋 Final fulfillment data:`, JSON.stringify(fulfillmentData, null, 2));

    // Create fulfillment using Shopify REST API
    const fulfillmentResponse = await restClient.post(
      `/orders/${numericOrderId}/fulfillments.json`,
      fulfillmentData
    );

    console.log(`✅ Fulfillment created successfully:`, fulfillmentResponse);

    res.json({
      success: true,
      fulfillment: fulfillmentResponse,
      message: "Fulfillment created successfully",
      trackingNumber: fulfillmentData.fulfillment?.tracking_number,
      trackingCompany: fulfillmentData.fulfillment?.tracking_company
    });

  } catch (error) {
    console.error("❌ Error creating fulfillment:", error);
    console.error("❌ Error stack:", error.stack);
    
    // Ensure we always return JSON, never HTML
    res.setHeader('Content-Type', 'application/json');
    
    if (error.response) {
      console.error("❌ Shopify API Error Response:");
      console.error("📊 Status:", error.response.status || error.response.statusCode);
      console.error("📋 Headers:", error.response.headers);
      console.error("📄 Body:", error.response.body || error.response.data);
      // Avoid circular reference error when logging response
      try {
        const responseForLogging = {
          status: error.response.status,
          statusText: error.response.statusText,
          headers: error.response.headers,
          data: error.response.data
        };
        console.error("🔍 Full Response:", JSON.stringify(responseForLogging, null, 2));
      } catch (circularError) {
        console.error("⚠️ Response contains circular references, skipping full log");
      }
      
      // Special handling for 406 errors
      if (error.response.status === 406 || error.response.statusCode === 406) {
        console.error("🚨 406 NOT ACCEPTABLE - Common causes:");
        console.error("   - Order not fulfillable (already fulfilled, cancelled, etc.)");
        console.error("   - Line items already fulfilled or invalid");
        console.error("   - Inventory tracking issues");
        console.error("   - API version compatibility");
        console.error("   - Missing required fields");
      }
      
      return res.status(error.response.statusCode || error.response.status || 500).json({
        error: "Shopify API Error",
        message: error.response.body?.errors || error.response.data?.errors || error.message,
        details: error.response.body || error.response.data,
        shopifyStatus: error.response.status || error.response.statusCode,
        timestamp: new Date().toISOString()
      });
    }

    return res.status(500).json({
      error: "Internal Server Error",
      message: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Fulfillment endpoint using Shopify REST API
 * Uses REST API to avoid GraphQL permission issues on Grow plan
 */
app.post("/fulfillments/v2", authenticate, async (req, res) => {
  console.log("🚚 ===============================================");
  console.log("🚚 Creating fulfillment via Shopify REST API");

  try {
    const { orderId, trackingCompany, trackingNumber, notifyCustomer = true } = req.body;

    if (!orderId || !trackingCompany || !trackingNumber) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields: orderId, trackingCompany, trackingNumber"
      });
    }

    console.log(`📦 Order ID: ${orderId}`);
    console.log(`🚚 Tracking: ${trackingCompany} - ${trackingNumber}`);

    // Extract numeric order ID from GID
    const numericOrderId = orderId.toString().replace(/^gid:\/\/shopify\/Order\//, '');
    console.log(`🔢 Numeric Order ID: ${numericOrderId}`);

    // Get the first available location
    console.log(`🏪 Getting store locations to set location_id...`);
    const locationsResponse = await restClient.get('/locations.json');
    const locations = locationsResponse.locations || [];
    
    if (locations.length === 0) {
      throw new Error('No locations found in store');
    }

    const locationId = locations[0].id;
    console.log(`📍 Using location_id: ${locationId} (${locations[0].name || 'Default'})`);

    // Pre-check: Verify order exists and is fulfillable
    console.log(`🔍 Fetching order details for pre-check...`);
    try {
      const orderCheckResponse = await restClient.get(`/orders/${numericOrderId}.json`);
      const orderDetails = orderCheckResponse.order;
      
      console.log(`📋 Order Status Check:`);
      console.log(`   💰 Financial Status: ${orderDetails.financial_status}`);
      console.log(`   📦 Fulfillment Status: ${orderDetails.fulfillment_status || 'unfulfilled'}`);
      console.log(`   🏷️ Tags: ${orderDetails.tags || 'none'}`);
      console.log(`   📅 Created: ${orderDetails.created_at}`);
      console.log(`   📝 Line Items: ${orderDetails.line_items?.length || 0}`);

      if (orderDetails.financial_status?.toLowerCase() !== 'paid') {
        throw new Error(`Order must be paid before fulfillment. Current status: ${orderDetails.financial_status}`);
      }

      if (orderDetails.fulfillment_status?.toLowerCase() === 'fulfilled') {
        throw new Error(`Order is already fully fulfilled.`);
      }

      console.log(`✅ Order appears fulfillable, proceeding with fulfillment creation...`);
      
    } catch (orderFetchError) {
      console.error(`⚠️ Could not fetch order details for pre-check:`, orderFetchError.message);
      console.log(`🔄 Proceeding with fulfillment anyway...`);
    }

    // Create fulfillment payload
    const fulfillmentPayload = {
      fulfillment: {
        location_id: locationId,
        tracking_number: trackingNumber,
        tracking_company: trackingCompany,
        notify_customer: notifyCustomer
      }
    };

    console.log(`🔍 Making Shopify REST API call:`);
    console.log(`📍 URL: /orders/${numericOrderId}/fulfillments.json`);
    console.log(`🔐 Using API version: ${SHOPIFY_API_VERSION}`);
    console.log(`🏪 Store: ${SHOPIFY_STORE_URL}`);
    console.log(`📋 Final fulfillment data:`, JSON.stringify(fulfillmentPayload, null, 2));

    // Create fulfillment using Shopify REST API
    const fulfillmentResponse = await restClient.post(
      `/orders/${numericOrderId}/fulfillments.json`,
      fulfillmentPayload
    );

    console.log(`✅ Fulfillment created successfully:`, fulfillmentResponse);

    res.json({
      success: true,
      fulfillment: fulfillmentResponse,
      message: "Fulfillment created successfully via REST API",
      trackingNumber: trackingNumber,
      trackingCompany: trackingCompany
    });

  } catch (error) {
    console.error("❌ Error creating fulfillment:", error);
    console.error("❌ Error stack:", error.stack);
    
    // Ensure we always return JSON, never HTML
    res.setHeader('Content-Type', 'application/json');
    
    if (error.response) {
      console.error("❌ Shopify API Error Response:");
      console.error("📊 Status:", error.response.status || error.response.statusCode);
      console.error("📋 Headers:", error.response.headers);
      console.error("📄 Body:", error.response.body || error.response.data);
      
      // Avoid circular reference error when logging response
      try {
        const responseForLogging = {
          status: error.response.status,
          statusText: error.response.statusText,
          headers: error.response.headers,
          data: error.response.data
        };
        console.error("🔍 Full Response:", JSON.stringify(responseForLogging, null, 2));
      } catch (circularError) {
        console.error("⚠️ Response contains circular references, skipping full log");
      }
      
      // Special handling for 406 errors
      if (error.response.status === 406 || error.response.statusCode === 406) {
        console.error("🚨 406 NOT ACCEPTABLE - Common causes:");
        console.error("   - Order not fulfillable (already fulfilled, cancelled, etc.)");
        console.error("   - Line items already fulfilled or invalid");
        console.error("   - Inventory tracking issues");
        console.error("   - API version compatibility");
        console.error("   - Missing required fields");
        console.error("💡 Check: order fulfillment status, location_id, and line item availability");
      }
      
      return res.status(error.response.statusCode || error.response.status || 500).json({
        error: "Shopify API Error",
        message: error.response.body?.errors || error.response.data?.errors || error.message,
        details: error.response.body || error.response.data,
        shopifyStatus: error.response.status || error.response.statusCode,
        timestamp: new Date().toISOString()
      });
    }

    return res.status(500).json({
      error: "Internal Server Error",
      message: error.message,
      timestamp: new Date().toISOString()
    });
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

    // Fetch note_attributes for all orders via REST API (for business_name, customer_name, etc.)
    console.log("📋 Fetching note_attributes for all orders...");
    let restOrdersMap = {};
    try {
      const restOrdersRes = await restClient.get(`/orders.json?limit=250&status=any`);
      restOrdersRes.orders.forEach((order) => {
        const noteAttributes = {};
        order.note_attributes.forEach((na) => {
          noteAttributes[na.name] = na.value;
        });
        restOrdersMap[order.id] = noteAttributes;
      });
      console.log(`✅ Fetched note_attributes for ${Object.keys(restOrdersMap).length} orders`);
    } catch (restError) {
      console.warn("⚠️ Could not fetch note_attributes via REST:", restError.message);
    }

    // Transform the data with smart naming
    const transformedOrders = orders.map(({ node }) => {
      const metafields = {};
      node.metafields.edges.forEach((mf) => {
        metafields[mf.node.key] = mf.node.value;
      });

      // Get note_attributes for this order
      const noteAttributes = restOrdersMap[node.legacyResourceId] || {};

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

      // Smart naming logic - prioritize attributes over default names
      const businessName = noteAttributes.business_name || noteAttributes.company_name || node.shippingAddress?.company || node.customer?.displayName || 'Unknown';
      const customerName = noteAttributes.customer_name || node.customer?.displayName || noteAttributes.business_name || 'Unknown Customer';
      
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
        attributes: noteAttributes,
        // Smart display names (prioritizes custom attributes)
        display_business_name: businessName,
        display_customer_name: customerName,
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
      console.log(`✅ Fetched note_attributes for order ${legacyId}:`, Object.keys(noteAttributes));
    } catch (restError) {
      console.warn("⚠️ Could not fetch note_attributes via REST:", restError.message);
    }

    // Smart naming logic - prioritize attributes over default names
    const businessName = noteAttributes.business_name || noteAttributes.company_name || node.shippingAddress?.company || node.customer?.displayName || 'Unknown';
    const customerName = noteAttributes.customer_name || node.customer?.displayName || noteAttributes.business_name || 'Unknown Customer';

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
      // Smart display names (prioritizes custom attributes)
      display_business_name: businessName,
      display_customer_name: customerName,
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

/**
 * Shopify webhook endpoint for order creation
 * Creates a deal in HubSpot when a new order is placed
 */
app.post("/shopify-webhook", async (req, res) => {
  try {
    console.log("🛒 Shopify webhook received - Order created");
    console.log("🔍 Headers:", req.headers);
    console.log("🔍 Raw body type:", typeof req.body);
    
    if (!hubspotClient) {
      console.log("⚠️ HubSpot client not available - cannot create deal");
      return res.status(200).json({ received: true, processed: false, message: "HubSpot not configured" });
    }

    let order;
    try {
      order = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    } catch (parseError) {
      console.error("❌ Failed to parse Shopify webhook payload:", parseError.message);
      return res.status(200).json({ received: true, processed: false, message: "Invalid JSON payload" });
    }

    console.log("🛒 Shopify order received:", JSON.stringify(order, null, 2));

    // Create HubSpot deal from Shopify order
    await createHubSpotDealFromShopifyOrder(order);

    res.status(200).json({ 
      received: true, 
      processed: true, 
      message: "Deal created in HubSpot successfully",
      orderId: order.id,
      orderNumber: order.name
    });

  } catch (error) {
    console.error("❌ Error processing Shopify webhook:", error.message);
    console.error("❌ Stack trace:", error.stack);
    
    // Always return 200 to prevent Shopify retries
    res.status(200).json({ 
      received: true, 
      processed: false, 
      error: error.message,
      message: "Error occurred but webhook acknowledged" 
    });
  }
});

/**
 * HubSpot webhook endpoint for deal stage changes
 * Bypasses authentication for webhook calls
 */
app.post("/webhook", async (req, res) => {
  try {
    console.log("🎯 HubSpot webhook received");
    console.log("🔍 Headers:", req.headers);
    console.log("🔍 Raw body type:", typeof req.body);
    console.log("🔍 Raw body:", req.body);

    if (!hubspotClient) {
      console.warn("⚠️ HubSpot webhook received but client not configured");
      return res.status(200).json({ 
        received: true, 
        processed: false, 
        message: "HubSpot integration not configured" 
      });
    }

    // Parse the webhook payload
    let payload;
    try {
      payload = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    } catch (parseError) {
      console.error("❌ Failed to parse webhook payload:", parseError.message);
      console.error("❌ Raw body:", req.body);
      return res.status(200).json({ received: true, processed: false, message: "Invalid JSON payload" });
    }

    console.log("📋 Webhook payload received:", JSON.stringify(payload, null, 2));
    console.log("📋 Payload type:", typeof payload);
    console.log("📋 Is array:", Array.isArray(payload));
    console.log("📋 Payload length:", payload?.length);

    // Handle different payload formats
    let dealData;
    
    // Case 1: Array format (most common HubSpot format)
    if (Array.isArray(payload) && payload.length > 0) {
      dealData = payload[0];
    }
    // Case 2: Single object format
    else if (payload && typeof payload === 'object' && !Array.isArray(payload)) {
      dealData = payload;
    }
    // Case 3: Empty or invalid
    else {
      console.warn("⚠️ Webhook payload is not an array or object, or is empty");
      console.warn("⚠️ Payload:", payload);
      return res.status(200).json({ 
        received: true, 
        processed: false, 
        message: "Empty or invalid payload format",
        debug: {
          type: typeof payload,
          isArray: Array.isArray(payload),
          length: payload?.length,
          payload: payload
        }
      });
    }

    const { objectId, propertyName, newValue, propertyValue } = dealData;
    
    // HubSpot can send either 'newValue' or 'propertyValue'
    const value = newValue || propertyValue;

    console.log(`🔍 Processing: objectId=${objectId}, propertyName=${propertyName}, value=${value}`);
    console.log(`🔍 Deal data keys:`, Object.keys(dealData));

    // Check if this is a dealstage change to closedwon
    if (propertyName === 'dealstage' && value === 'closedwon') {
      console.log(`🎉 Deal ${objectId} moved to 'closedwon' - creating Shopify order`);

      try {
        const result = await createShopifyOrderFromHubspotInvoice(objectId);
        
        console.log(`✅ Successfully created Shopify order from HubSpot deal ${objectId}`);
        
        return res.status(200).json({
          received: true,
          processed: true,
          message: "Shopify order created successfully",
          dealId: objectId,
          shopifyOrder: result.order
        });

      } catch (orderError) {
        console.error(`❌ Failed to create Shopify order from deal ${objectId}:`, orderError.message);
        
        // Still return 200 to prevent HubSpot retries, but log the error
        return res.status(200).json({
          received: true,
          processed: false,
          message: "Failed to create Shopify order",
          error: orderError.message,
          dealId: objectId
        });
      }

    } else {
      console.log(`ℹ️ Webhook ignored - not a dealstage change to closedwon (propertyName: ${propertyName}, newValue: ${newValue})`);
      
      return res.status(200).json({
        received: true,
        processed: false,
        message: `Webhook ignored - not a dealstage change to closedwon`,
        propertyName,
        value
      });
    }

  } catch (error) {
    console.error("❌ Webhook processing error:", error);
    
    // Always return 200 for webhooks to prevent retries
    return res.status(200).json({
      received: true,
      processed: false,
      message: "Webhook processing failed",
      error: error.message
    });
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
      "GET /fulfillments/test",
      "POST /fulfillments",
      "POST /upload-file",
      "POST /webhook",
      "POST /shopify-webhook"
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
  console.log(`✅ HubSpot Integration: ${hubspotClient ? 'Enabled' : 'Disabled'}`);
  console.log("✅ ===============================================");
  console.log("🔗 Available endpoints:");
  console.log("   📊 GET  /meta              - Server & store info");
  console.log("   📋 GET  /orders            - Orders with pagination");
  console.log("   🔍 GET  /orders/:id        - Individual order");
  console.log("   🔄 GET  /rest/orders/:id   - REST fallback");
  console.log("   🏢 GET  /rest/locations    - Store locations");
  console.log("   📝 GET  /metafields        - Metafields help");
  console.log("   💾 POST /metafields        - Manage metafields");
  console.log("   📦 POST /fulfillments      - Create order fulfillments (REST)");
  console.log("   ✨ POST /fulfillments/v2   - Create order fulfillments (GraphQL v2)");
  console.log("   🧪 GET  /fulfillments/test - Test fulfillment endpoint");
  console.log("   📤 POST /upload-file       - File uploads");
  console.log("   🎯 POST /webhook           - HubSpot webhook handler");
  console.log("   🛒 POST /shopify-webhook   - Shopify order webhook");
  console.log("✅ ===============================================");
}); 
