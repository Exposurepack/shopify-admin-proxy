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
  // Bypass authentication for webhook endpoints
  if (req.path === '/webhook' || req.path === '/shopify-webhook') {
    return next();
  }
  
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
              'dealname',
              'amount',
              'dealstage',
              'closedate',
              'hs_object_id',
              'notes_last_contacted',
              'description',
              'deal_currency_code',
              'hs_deal_stage_probability',
              'hubspot_owner_id'
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
              'firstname',
              'lastname',
              'email',
              'phone',
              'company',
              'address',
              'city',
              'state',
              'zip',
              'country'
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
      
      // Fetch detailed invoice data including line items and tax
      // First, try with all properties to see what's available
      const invoiceResponse = await axios.get(
        `${this.baseURL}/crm/v3/objects/invoices/${invoiceId}`,
        {
          headers: this.headers,
          params: {
            // Request all properties to see what's available
            properties: 'all',
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
      deal_description: `Order imported from Shopify\nOrder #: ${order.name}\nItems: ${order.line_items?.length || 0}\nCustomer: ${customer.email || 'N/A'}`
    };

    console.log(`🤝 Creating deal: ${dealData.dealname} - $${dealAmount} ${currency}`);

    // Create deal in HubSpot
    const deal = await hubspotClient.createDeal(dealData);
    console.log(`✅ Created HubSpot deal: ${deal.id} - ${dealData.dealname}`);

    // Associate contact with deal if both exist
    if (contact && deal) {
      await hubspotClient.associateContactWithDeal(contact.id, deal.id);
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
      const totalAmount = parseFloat(props.amount) || (unitPrice * originalQuantity) || 0;
      
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

    // Build customer data
    const customer = {
      first_name: contactProps.firstname || '',
      last_name: contactProps.lastname || '',
      email: contactProps.email || `hubspot-${dealId}@placeholder.com`,
      phone: contactProps.phone || null
    };

    // Build address (use contact address or company address)
    const address = {
      first_name: contactProps.firstname || '',
      last_name: contactProps.lastname || '',
      company: contactProps.company || '',
      address1: contactProps.address || '',
      city: contactProps.city || '',
      province: contactProps.state || '',
      country: contactProps.country || 'Australia', // Default for AU business
      zip: contactProps.zip || '',
      phone: contactProps.phone || null
    };

    // Create order via Shopify REST API
    const orderData = {
      order: {
        line_items: shopifyLineItems,
        customer: customer,
        billing_address: address,
        shipping_address: address,
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

    // Create the order using REST API
    const response = await restClient.post('/orders.json', orderData);
    const createdOrder = response.order;

    console.log(`✅ Successfully created Shopify order: ${createdOrder.name} (ID: ${createdOrder.id})`);

    // Add additional metafields for tracking
    const orderGID = `gid://shopify/Order/${createdOrder.id}`;
    await metafieldManager.setMetafield(
      orderGID,
      'hubspot',
      'deal_id',
      dealId,
      'single_line_text_field'
    );

    await metafieldManager.setMetafield(
      orderGID,
      'hubspot',
      'deal_name',
      deal.properties.dealname || '',
      'single_line_text_field'
    );

    await metafieldManager.setMetafield(
      orderGID,
      'hubspot',
      'original_amount',
      deal.properties.amount || '0',
      'number_decimal'
    );

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
 * Fulfillment endpoint - Creates Shopify fulfillments with tracking info
 */
app.post("/fulfillments", authenticate, async (req, res) => {
  try {
    const { orderId, fulfillmentData } = req.body;

    if (!orderId || !fulfillmentData) {
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
    
    if (error.response?.body) {
      console.error("❌ Shopify API Error Details:", error.response.body);
      
      return res.status(error.response.statusCode || 500).json({
        error: "Shopify API Error",
        message: error.response.body.errors || error.message,
        details: error.response.body
      });
    }

    res.status(500).json({
      error: "Internal Server Error",
      message: error.message
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
  console.log("   📦 POST /fulfillments      - Create order fulfillments");
  console.log("   📤 POST /upload-file       - File uploads");
  console.log("   🎯 POST /webhook           - HubSpot webhook handler");
  console.log("   🛒 POST /shopify-webhook   - Shopify order webhook");
  console.log("✅ ===============================================");
}); 
