import express from "express";
import axios from "axios";
import cors from "cors";
import dotenv from "dotenv";
import multer from "multer";
import FormData from "form-data";
import rateLimit from "express-rate-limit";
import helmet from "helmet";
import session from "express-session";
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

dotenv.config();

// Environment variables with validation
const {
  SHOPIFY_STORE_URL,
  SHOPIFY_ACCESS_TOKEN,
  SHOPIFY_API_VERSION = "2024-10",
  FRONTEND_SECRET,
  HUBSPOT_PRIVATE_APP_TOKEN,
  HUBSPOT_PIPELINE_ID,
  HUBSPOT_CLOSED_WON_STAGE,
  PORT = 10000,
  NODE_ENV = "development",
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_CALLBACK_URL,
  GOOGLE_REDIRECT_URI,
  SESSION_SECRET,
  GA4_PROPERTY_ID,
  GA4_DEFAULT_PROPERTY_ID,
  ADS_DEVELOPER_TOKEN,
  ADS_LOGIN_CUSTOMER_ID,
  ADS_DEFAULT_CUSTOMER_ID
} = process.env;

const LOG_VERBOSE = process.env.LOG_VERBOSE === 'true';

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

if (!SESSION_SECRET) {
  console.warn("⚠️ SESSION_SECRET not set. Using a fallback is insecure; set SESSION_SECRET in env.");
}
if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_CALLBACK_URL) {
  console.warn("⚠️ Google OAuth envs not fully set (GOOGLE_CLIENT_ID/SECRET/CALLBACK_URL). OAuth endpoints will fail until configured.");
}
if (!ADS_DEVELOPER_TOKEN) {
  console.warn("⚠️ ADS_DEVELOPER_TOKEN not set - Google Ads API routes will return 400 until configured");
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
  /\.shopifypreview\.com$/,
  /localhost:\d+$/,
  'https://www.exposurepack.com.au',
  'https://exposurepack.com.au',
  'http://www.exposurepack.com.au',
  'http://exposurepack.com.au',
  /\.exposurepack\.com\.au$/
];

const corsOptions = {
  origin: function (origin, callback) {
    if (LOG_VERBOSE) console.log('🌐 CORS check for origin:', origin);
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      if (LOG_VERBOSE) console.log('✅ CORS: No origin header - allowing');
      return callback(null, true);
    }
    
    // In development, allow all origins
    if (NODE_ENV !== "production") {
      if (LOG_VERBOSE) console.log('✅ CORS: Development mode - allowing all origins');
      return callback(null, true);
    }
    
    // Check against allowed origins
    const isAllowed = allowedOrigins.some(allowedOrigin => {
      if (typeof allowedOrigin === 'string') {
        const matches = origin === allowedOrigin;
        if (LOG_VERBOSE) console.log(`🔍 CORS: Checking string "${allowedOrigin}" against "${origin}": ${matches}`);
        return matches;
      } else if (allowedOrigin instanceof RegExp) {
        const matches = allowedOrigin.test(origin);
        if (LOG_VERBOSE) console.log(`🔍 CORS: Checking regex ${allowedOrigin} against "${origin}": ${matches}`);
        return matches;
      }
      return false;
    });
    
    if (isAllowed) {
      if (LOG_VERBOSE) console.log('✅ CORS: Origin allowed');
      callback(null, true);
    } else {
      console.log('❌ CORS: Origin not allowed');
      console.log('📋 CORS: Allowed origins:', allowedOrigins);
      callback(new Error('Not allowed by CORS'));
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-api-key', 'X-API-Key'],
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

// Session (required for OAuth with cookies; cross-site needs SameSite=None)
app.use(session({
  secret: SESSION_SECRET || 'change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: NODE_ENV === 'production' ? 'none' : 'lax',
    secure: NODE_ENV === 'production',
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
}));

// Passport (Google)
passport.serializeUser((user, done) => {
  done(null, { id: user?.id || user?.profile?.id || user?.emails?.[0]?.value || 'google' });
});
passport.deserializeUser((obj, done) => done(null, obj));

passport.use(new GoogleStrategy(
  {
    clientID: GOOGLE_CLIENT_ID || "",
    clientSecret: GOOGLE_CLIENT_SECRET || "",
    callbackURL: GOOGLE_CALLBACK_URL || GOOGLE_REDIRECT_URI || "",
  },
  (accessToken, refreshToken, profile, done) => {
    const user = {
      id: profile?.id,
      profile,
      tokens: {
        accessToken,
        refreshToken: refreshToken || null,
        expiryDate: Date.now() + 3500 * 1000
      }
    };
    return done(null, user);
  }
));

app.use(passport.initialize());
app.use(passport.session());

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
  // Bypass authentication for webhook endpoints, test endpoints, and Google OAuth paths
  if (
    req.path === '/webhook' ||
    req.path === '/shopify-webhook' ||
    req.path === '/shopify-customer-webhook' ||
    req.path === '/fulfillments/test' ||
    req.path === '/fulfillments/v2/test' ||
    (req.path === '/fulfillments' && req.method === 'GET') ||
    (req.path === '/fulfillments/v2' && req.method === 'GET') ||
    req.path.startsWith('/auth/google')
  ) {
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

  async getQuote(quoteId) {
    try {
      const response = await axios.get(
        `${this.baseURL}/crm/v3/objects/quotes/${quoteId}`,
        {
          headers: this.headers,
          params: {
            properties: [
              'hs_object_id', 'hs_createdate', 'hs_lastmodifieddate',
              'hs_quote_number', 'name', 'status',
              // Common quote address field patterns
              'ship_to_address', 'ship_to_street', 'ship_to_city', 'ship_to_state', 'ship_to_zip',
              'bill_to_address', 'bill_to_street', 'bill_to_city', 'bill_to_state', 'bill_to_zip',
              'shipping_address', 'shipping_street', 'shipping_city', 'shipping_state', 'shipping_zip',
              'billing_address', 'billing_street', 'billing_city', 'billing_state', 'billing_zip',
              'delivery_address', 'delivery_street', 'delivery_city', 'delivery_state', 'delivery_zip',
              'customer_address', 'customer_street', 'customer_city', 'customer_state', 'customer_zip',
              // Alternative common patterns
              'address', 'address1', 'address2', 'address_line_1', 'address_line_2', 'street', 'city', 'state', 'zip', 'postal_code', 'postcode',
              // System-prefixed variants
              'hs_ship_to_address', 'hs_ship_to_address_2', 'hs_ship_to_city', 'hs_ship_to_state', 'hs_ship_to_zip', 'hs_ship_to_country',
              'hs_bill_to_address', 'hs_bill_to_address_2', 'hs_bill_to_city', 'hs_bill_to_state', 'hs_bill_to_zip', 'hs_bill_to_country',
              'hs_shipping_address', 'hs_shipping_address_2', 'hs_shipping_city', 'hs_shipping_state', 'hs_shipping_zip', 'hs_shipping_country',
              'hs_billing_address', 'hs_billing_address_2', 'hs_billing_city', 'hs_billing_state', 'hs_billing_zip', 'hs_billing_country'
            ].join(',')
          },
          timeout: 30000
        }
      );
      return response.data;
    } catch (error) {
      console.warn(`⚠️ Failed to fetch quote ${quoteId}:`, error.response?.data?.message || error.message);
      return null;
    }
  }

  async getAssociatedQuotes(dealId) {
    try {
      const response = await axios.get(
        `${this.baseURL}/crm/v3/objects/deals/${dealId}/associations/quotes`,
        {
          headers: this.headers,
          timeout: 30000
        }
      );

      if (!response.data.results || response.data.results.length === 0) {
        return [];
      }

      const quotePromises = response.data.results.map(association => 
        this.getQuote(association.id)
      );

      return (await Promise.all(quotePromises)).filter(Boolean);
    } catch (error) {
      console.warn(`⚠️ Failed to fetch associated quotes for deal ${dealId}:`, error.response?.data?.message || error.message);
      return [];
    }
  }

  // Helper to fetch deal pipelines and resolve Closed Won stage
  async resolveClosedWonStage(preferredPipelineName = 'deals pipeline') {
    // Env override if provided
    if (HUBSPOT_PIPELINE_ID && HUBSPOT_CLOSED_WON_STAGE) {
      return { pipelineId: HUBSPOT_PIPELINE_ID, stageId: HUBSPOT_CLOSED_WON_STAGE };
    }
    const res = await axios.get(`${this.baseURL}/crm/v3/pipelines/deals`, { headers: this.headers });
    const pipelines = res.data?.results || [];

    const pipeline = pipelines.find(p => (p.label || '').toLowerCase() === preferredPipelineName.toLowerCase())
      || pipelines.find(p => p.displayOrder === 0)
      || pipelines[0];

    const stages = pipeline?.stages || [];
    const closedWon = stages.find(s => (s.label || '').toLowerCase().includes('closed won'))
      || stages.find(s => (s.id || '').toLowerCase() === 'closedwon')
      || stages[stages.length - 1];

    return { pipelineId: pipeline?.id || 'default', stageId: closedWon?.id || 'closedwon' };
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
              'billing_street', 'billing_city', 'billing_state', 'billing_zip',
              // Include HubSpot system-prefixed variants
              'hs_ship_to_address', 'hs_ship_to_address_2', 'hs_ship_to_city', 'hs_ship_to_state', 'hs_ship_to_zip', 'hs_ship_to_country',
              'hs_bill_to_address', 'hs_bill_to_address_2', 'hs_bill_to_city', 'hs_bill_to_state', 'hs_bill_to_zip', 'hs_bill_to_country',
              'hs_shipping_address', 'hs_shipping_address_2', 'hs_shipping_city', 'hs_shipping_state', 'hs_shipping_zip', 'hs_shipping_country',
              'hs_billing_address', 'hs_billing_address_2', 'hs_billing_city', 'hs_billing_state', 'hs_billing_zip', 'hs_billing_country'
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
              'address_line_1', 'address_line_2', 'postal_code', 'postcode',
              // System-prefixed variants (rare on contacts, but safe to include)
              'hs_address', 'hs_city', 'hs_state', 'hs_zip', 'hs_country'
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

  async getCompany(companyId) {
    try {
      const response = await axios.get(
        `${this.baseURL}/crm/v3/objects/companies/${companyId}`,
        {
          headers: this.headers,
          params: {
            properties: [
              'name', 'domain', 'website', 'phone',
              'address', 'address2', 'street', 'address_line_1', 'address_line_2',
              'city', 'state', 'country', 'zip', 'postal_code', 'postcode'
            ].join(',')
          },
          timeout: 30000
        }
      );
      return response.data;
    } catch (error) {
      throw new Error(`Failed to fetch HubSpot company ${companyId}: ${error.response?.data?.message || error.message}`);
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
              'customer_address', 'customer_street', 'customer_city', 'customer_state', 'customer_zip',
              // System-prefixed variants
              'hs_ship_to_address', 'hs_ship_to_address_2', 'hs_ship_to_city', 'hs_ship_to_state', 'hs_ship_to_zip', 'hs_ship_to_country',
              'hs_bill_to_address', 'hs_bill_to_address_2', 'hs_bill_to_city', 'hs_bill_to_state', 'hs_bill_to_zip', 'hs_bill_to_country',
              'hs_shipping_address', 'hs_shipping_address_2', 'hs_shipping_city', 'hs_shipping_state', 'hs_shipping_zip', 'hs_shipping_country',
              'hs_billing_address', 'hs_billing_address_2', 'hs_billing_city', 'hs_billing_state', 'hs_billing_zip', 'hs_billing_country'
            ].join(','),
            associations: 'line_items,quotes,companies,contacts'
          }
        }
      );
      
      console.log(`📄 Invoice details response:`, JSON.stringify(invoiceResponse.data, null, 2));

      let invoice = invoiceResponse.data;

      // Dynamic property discovery: if no address-like keys returned, refetch with all relevant props
      const hasAddressLikeKey = (propsObj) => Object.keys(propsObj || {}).some(k =>
        /address|address1|address_1|street|city|state|province|region|zip|postcode|postal|ship|bill|delivery/i.test(k)
      );

      if (!hasAddressLikeKey(invoice.properties)) {
        try {
          console.log(`🔎 No address-like keys on invoice. Discovering invoice properties...`);
          const propsDef = await axios.get(`${this.baseURL}/crm/v3/properties/invoices`, { headers: this.headers });
          const allNames = (propsDef.data?.results || []).map(p => p.name);
          const wanted = allNames.filter(n => /address|address1|address_1|street|city|state|province|region|zip|postcode|postal|ship|bill|delivery|hs_tax_amount|hs_total_amount|hs_subtotal_amount|hs_discount_amount|hs_invoice_number|hs_currency/i.test(n));
          if (wanted.length > 0) {
            const refetch = await axios.get(
              `${this.baseURL}/crm/v3/objects/invoices/${invoiceId}`,
              {
                headers: this.headers,
                params: { properties: wanted.join(','), associations: 'line_items,quotes,companies,contacts' }
              }
            );
            invoice = refetch.data;
            console.log(`🔁 Refetched invoice with ${wanted.length} properties (dynamic)`);
          }
        } catch (discErr) {
          console.log(`ℹ️ Invoice property discovery failed:`, discErr.message);
        }
      }
      
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
          id: invoiceId,
          number: invoice.properties.hs_invoice_number || `INV-${invoiceId}`,
          subtotal: subtotal,
          tax: tax,
          discount: parseFloat(invoice.properties.hs_discount_amount) || 0,
          total: total,
          currency: invoice.properties.hs_currency || 'AUD',
          // Include full properties so downstream address extraction can work
          properties: invoice.properties,
          associations: invoice.associations || {}
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

  async getAssociatedCompanies(dealId) {
    try {
      const response = await axios.get(
        `${this.baseURL}/crm/v3/objects/deals/${dealId}/associations/companies`,
        {
          headers: this.headers,
          timeout: 30000
        }
      );

      if (!response.data.results || response.data.results.length === 0) {
        return [];
      }

      const companyPromises = response.data.results.map(association => 
        this.getCompany(association.id)
      );

      return await Promise.all(companyPromises);
    } catch (error) {
      console.warn(`⚠️ Failed to fetch associated companies for deal ${dealId}:`, error.response?.data?.message || error.message);
      return [];
    }
  }

  async getCompaniesForContact(contactId) {
    try {
      const response = await axios.get(
        `${this.baseURL}/crm/v3/objects/contacts/${contactId}/associations/companies`,
        {
          headers: this.headers,
          timeout: 30000
        }
      );

      if (!response.data.results || response.data.results.length === 0) {
        return [];
      }

      const companyPromises = response.data.results.map(association => 
        this.getCompany(association.id)
      );

      return await Promise.all(companyPromises);
    } catch (error) {
      console.warn(`⚠️ Failed to fetch companies for contact ${contactId}:`, error.response?.data?.message || error.message);
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

  async upsertDealByProperty(idProperty, properties) {
    try {
      const url = `${this.baseURL}/crm/v3/objects/deals?idProperty=${encodeURIComponent(idProperty)}`;
      const resp = await axios.post(url, { properties }, { headers: this.headers });
      console.log(`✅ Upserted deal by ${idProperty}: ${resp.data.id}`);
      return resp.data;
    } catch (error) {
      const msg = error.response?.data?.message || error.message;
      console.warn(`⚠️ Upsert by ${idProperty} failed, will fallback to create: ${msg}`);
      // Fallback to normal create
      return await this.createDeal(properties);
    }
  }

  async associateContactWithDeal(contactId, dealId) {
    try {
      console.log(`🔗 Associating contact ${contactId} with deal ${dealId}`);
      
      // Use association label instead of hard-coded numeric type to avoid portal-specific IDs
      const response = await axios.put(
        `${this.baseURL}/crm/v3/objects/deals/${dealId}/associations/contacts/${contactId}/deal_to_contact`,
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

  async getDealsForAnalytics(dateRange = null) {
    try {
      console.log(`📊 Fetching HubSpot deals for analytics...`);
      
      const params = {
        properties: [
          'dealname', 'amount', 'dealstage', 'closedate', 'createdate',
          'shopify_total_inc_gst', 'shopify_total_ex_gst', 'shopify_gst_amount',
          'shopify_subtotal', 'shopify_shipping_cost', 'shopify_order_number',
          'shopify_order_id', 'deal_source', 'hs_deal_currency_code',
          'hs_is_closed_won'
        ].join(','),
        limit: 100
      };

      // Always restrict to closed-won deals, and use closedate for range filtering (matches HubSpot reports)
      const filters = [
        { propertyName: 'hs_is_closed_won', operator: 'EQ', value: 'true' }
      ];
      if (dateRange && dateRange.startDate && dateRange.endDate) {
        const startTimestamp = new Date(dateRange.startDate).getTime();
        const endTimestamp = new Date(dateRange.endDate).getTime();
        filters.push({ propertyName: 'closedate', operator: 'BETWEEN', value: startTimestamp, highValue: endTimestamp });
      }
      params.filterGroups = JSON.stringify([{ filters }]);

      let allDeals = [];
      let hasMore = true;
      let after = 0;

      while (hasMore) {
        params.after = after;
        
        const response = await axios.post(
          `${this.baseURL}/crm/v3/objects/deals/search`,
          {
            filterGroups: params.filterGroups ? JSON.parse(params.filterGroups) : [],
            properties: params.properties.split(','),
            limit: params.limit,
            after: params.after
          },
          { headers: this.headers }
        );

        const deals = response.data.results || [];
        allDeals = allDeals.concat(deals);
        
        console.log(`📄 Fetched ${deals.length} deals, total: ${allDeals.length}`);
        
        hasMore = response.data.paging?.next?.after;
        after = hasMore;
        
        // Safety limit
        if (allDeals.length > 1000) {
          console.warn(`⚠️ Reached safety limit of 1000 deals`);
          break;
        }
      }

      console.log(`✅ Fetched ${allDeals.length} HubSpot deals for analytics`);
      return allDeals;

    } catch (error) {
      console.error(`❌ Failed to fetch HubSpot deals for analytics:`, error.response?.data?.message || error.message);
      throw error;
    }
  }

  async deleteDeal(dealId) {
    try {
      const response = await axios.delete(
        `${this.baseURL}/crm/v3/objects/deals/${dealId}`,
        { headers: this.headers }
      );
      return response.data;
    } catch (error) {
      throw new Error(`Failed to delete HubSpot deal ${dealId}: ${error.response?.data?.message || error.message}`);
    }
  }

  async searchDealsByShopifyOrder(legacyId, orderName) {
    try {
      const filterGroups = [];
      if (legacyId) {
        filterGroups.push({
          filters: [{ propertyName: 'shopify_order_id', operator: 'EQ', value: String(legacyId) }]
        });
      }
      if (orderName) {
        filterGroups.push({
          filters: [{ propertyName: 'shopify_order_number', operator: 'EQ', value: String(orderName) }]
        });
      }
      const response = await axios.post(
        `${this.baseURL}/crm/v3/objects/deals/search`,
        { filterGroups, properties: ['dealname','shopify_order_id','shopify_order_number'], limit: 100 },
        { headers: this.headers }
      );
      return response.data.results || [];
    } catch (error) {
      throw new Error(`Failed to search HubSpot deals for order: ${error.response?.data?.message || error.message}`);
    }
  }
}

/**
 * Error handling utilities
 */
const handleError = (error, res, defaultMessage = "An error occurred") => {
  const status = error.response?.status;
  const statusText = error.response?.statusText;
  const url = error.config?.url;
  const requestId = error.response?.headers?.['x-request-id'];
  const retryAfter = error.response?.headers?.['retry-after'];
  const details = error.response?.data?.errors || error.message;
  console.error("🔴 Error:", { message: defaultMessage, status, statusText, url, requestId, retryAfter, details });

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

    // Prepare contact data with separate billing and shipping addresses
    const contactData = {
      email: customer.email || billingAddress.email || 'unknown@shopify.com',
      firstname: customer.first_name || billingAddress.first_name || '',
      lastname: customer.last_name || billingAddress.last_name || '',
      phone: customer.phone || billingAddress.phone || '',
      company: billingAddress.company || shippingAddress.company || '',
      
      // Default contact address (use shipping address as primary, fallback to billing)
      address: shippingAddress.address1 || billingAddress.address1 || '',
      city: shippingAddress.city || billingAddress.city || '',
      state: shippingAddress.province || billingAddress.province || '',
      country: shippingAddress.country || billingAddress.country || '',
      zip: shippingAddress.zip || billingAddress.zip || '',
      
      // Billing address fields
      billing_address: billingAddress.address1 || '',
      billing_city: billingAddress.city || '',
      billing_state: billingAddress.province || '',
      billing_country: billingAddress.country || '',
      billing_zip: billingAddress.zip || '',
      billing_company: billingAddress.company || '',
      billing_first_name: billingAddress.first_name || '',
      billing_last_name: billingAddress.last_name || '',
      
      // Shipping address fields
      shipping_address: shippingAddress.address1 || '',
      shipping_city: shippingAddress.city || '',
      shipping_state: shippingAddress.province || '',
      shipping_country: shippingAddress.country || '',
      shipping_zip: shippingAddress.zip || '',
      shipping_company: shippingAddress.company || '',
      shipping_first_name: shippingAddress.first_name || '',
      shipping_last_name: shippingAddress.last_name || ''
    };

    // Create or update contact in HubSpot
    let contact;
    try {
      // Log address details being sent to HubSpot
      console.log(`📧 Contact data being sent to HubSpot:`);
      console.log(`   Email: ${contactData.email}`);
      console.log(`   Name: ${contactData.firstname} ${contactData.lastname}`);
      console.log(`   Company: ${contactData.company}`);
      console.log(`   Billing Address: ${contactData.billing_address}, ${contactData.billing_city}, ${contactData.billing_state} ${contactData.billing_zip}`);
      console.log(`   Shipping Address: ${contactData.shipping_address}, ${contactData.shipping_city}, ${contactData.shipping_state} ${contactData.shipping_zip}`);
      
      contact = await hubspotClient.createOrUpdateContact(contactData);
      console.log(`👤 Contact ready: ${contact.id} - ${contactData.email}`);
    } catch (contactError) {
      console.error(`❌ Failed to create contact, attempting fallback association: ${contactError.message}`);
      try {
        // Fallback: find existing contact by email directly and use it
        const searchRes = await axios.post(
          `${hubspotClient.baseURL}/crm/v3/objects/contacts/search`,
          { filterGroups: [{ filters: [{ propertyName: 'email', operator: 'EQ', value: contactData.email }] }] },
          { headers: hubspotClient.headers }
        );
        const hit = Array.isArray(searchRes?.data?.results) ? searchRes.data.results[0] : null;
        if (hit && hit.id) {
          contact = hit;
          console.log(`👤 Using existing HubSpot contact by search: ${hit.id} - ${contactData.email}`);
        }
      } catch (fallbackErr) {
        console.warn(`⚠️ Contact search fallback failed: ${fallbackErr.message}`);
      }
    }

    // Process line items - separate shipping items from products
    const allLineItems = order.line_items || [];
    const productLineItems = allLineItems.filter(item => 
      !item.title.toLowerCase().includes('shipping')
    );
    const shippingLineItems = allLineItems.filter(item => 
      item.title.toLowerCase().includes('shipping')
    );

    console.log(`📦 Processing ${allLineItems.length} total line items: ${productLineItems.length} products, ${shippingLineItems.length} shipping items`);

    // Calculate amounts
    const grossAmount = parseFloat(order.total_price) || 0;
    const subtotalAmount = parseFloat(order.subtotal_price) || 0;
    const taxAmount = parseFloat(order.total_tax) || 0;
    const shopifyShippingAmount = parseFloat(order.total_shipping_price_set?.shop_money?.amount) || 0;
    
    // Calculate total shipping cost (Shopify shipping + shipping line items)
    const shippingLineItemsTotal = shippingLineItems.reduce((sum, item) => 
      sum + (parseFloat(item.price) * parseInt(item.quantity)), 0
    );
    const totalShippingCost = shopifyShippingAmount + shippingLineItemsTotal;

    // Calculate ex-GST amounts (Australian GST is 10%)
    const gstRate = 0.10;
    const exGstAmount = grossAmount / (1 + gstRate);
    const calculatedGstAmount = grossAmount - exGstAmount;

    const currency = order.currency || 'AUD';

    console.log(`💰 Financial breakdown:`);
    console.log(`   Gross Total: $${grossAmount.toFixed(2)} ${currency}`);
    console.log(`   Ex-GST Total: $${exGstAmount.toFixed(2)} ${currency}`);
    console.log(`   GST Amount: $${calculatedGstAmount.toFixed(2)} ${currency}`);
    console.log(`   Shipping Total: $${totalShippingCost.toFixed(2)} ${currency}`);
    console.log(`   Subtotal: $${subtotalAmount.toFixed(2)} ${currency}`);

    // Resolve pipeline/stage and prepare minimal, valid properties for HubSpot
    const { pipelineId, stageId } = await hubspotClient.resolveClosedWonStage('deals pipeline');

    // Build desired deal name: "Business name - Customer first name"
    const businessName = (billingAddress.company || shippingAddress.company || customer?.default_address?.company || '').trim();
    const customerFirstName = (customer.first_name || shippingAddress.first_name || billingAddress.first_name || '').trim();
    const computedDealName = businessName
      ? `${businessName} - ${customerFirstName || 'Customer'}`
      : (customerFirstName || 'Customer');

    const dealData = {
      dealname: computedDealName,
      amount: exGstAmount,
      pipeline: pipelineId,
      dealstage: stageId,
      closedate: Date.now(),
      deal_currency_code: currency,
      // Source and Shopify identifiers for idempotency
      deal_source: 'shopify_webhook',
      shopify_order_id: String(order.id),
      shopify_order_number: String(order.name),
      // Financial breakdown for analytics
      shopify_total_inc_gst: grossAmount,
      shopify_total_ex_gst: exGstAmount,
      shopify_gst_amount: calculatedGstAmount,
      shopify_subtotal: subtotalAmount,
      shopify_shipping_cost: totalShippingCost
    };

    console.log(`🤝 Creating deal: ${dealData.dealname} - $${exGstAmount.toFixed(2)} ${currency} (ex-GST)`);
    console.log(`📊 Deal summary: ${productLineItems.length} product items, ${shippingLineItems.length} shipping items, Total: $${grossAmount.toFixed(2)} (inc GST)`);
    if (productLineItems.length > 0) {
      console.log(`📝 Product line items preview:`);
      productLineItems.forEach((item, i) => {
        console.log(`   ${i + 1}. ${item.title} (Qty: ${item.quantity}, $${parseFloat(item.price).toFixed(2)})`);
      });
    }
    if (shippingLineItems.length > 0) {
      console.log(`🚚 Shipping line items (processed as shipping cost):`);
      shippingLineItems.forEach((item, i) => {
        console.log(`   ${i + 1}. ${item.title} (Qty: ${item.quantity}, $${parseFloat(item.price).toFixed(2)})`);
      });
    }

    // Create or upsert deal in HubSpot by shopify_order_id (prevents duplicates across processes)
    let deal;
    try {
      deal = await hubspotClient.upsertDealByProperty('shopify_order_id', dealData);
    } catch (e) {
      console.warn('⚠️ Upsert failed; falling back to create:', e.response?.data?.message || e.message);
      deal = await hubspotClient.createDeal(dealData);
    }

    // Ensure stage/pipeline are correct in case HubSpot ignored on create
    if (deal?.properties?.dealstage !== stageId || deal?.properties?.pipeline !== pipelineId) {
      try {
        await axios.patch(
          `${hubspotClient.baseURL}/crm/v3/objects/deals/${deal.id}`,
          { properties: { pipeline: pipelineId, dealstage: stageId, closedate: Date.now() } },
          { headers: hubspotClient.headers }
        );
        console.log(`✅ Normalized deal ${deal.id} to pipeline=${pipelineId}, stage=${stageId}`);
      } catch (patchErr) {
        console.warn(`⚠️ Failed to normalize deal stage/pipeline for ${deal.id}:`, patchErr.message);
      }
    }
    console.log(`✅ Created HubSpot deal: ${deal.id} - ${dealData.dealname}`);

    // Annotate Shopify order with HubSpot deal reference for cross-system idempotency
    try {
      const numericOrderId = order.id;
      const res = await restClient.get(`/orders/${numericOrderId}.json?fields=id,tags,note_attributes`);
      const currentTags = String(res?.order?.tags || '');
      const tagSet = new Set(currentTags.split(',').map(t => t.trim()).filter(Boolean));
      ['hubspot', 'hubspot-linked', `hubspot-deal-${deal.id}`].forEach(t => tagSet.add(t));
      const updatedTags = Array.from(tagSet).join(', ');

      const existingNotes = Array.isArray(res?.order?.note_attributes) ? res.order.note_attributes : [];
      const hasNote = existingNotes.some(na => String(na.name).toLowerCase() === 'hubspot_deal_id');
      const updatedNotes = hasNote
        ? existingNotes.map(na => (String(na.name).toLowerCase() === 'hubspot_deal_id' ? { name: 'hubspot_deal_id', value: String(deal.id) } : na))
        : existingNotes.concat([{ name: 'hubspot_deal_id', value: String(deal.id) }]);

      await restClient.put(`/orders/${numericOrderId}.json`, { order: { id: numericOrderId, tags: updatedTags, note_attributes: updatedNotes }});
      console.log(`✅ Annotated Shopify order ${order.name} with HubSpot deal ID ${deal.id}`);
    } catch (annotateErr) {
      console.warn(`⚠️ Could not annotate Shopify order with HubSpot deal ID:`, annotateErr?.response?.data || annotateErr.message);
    }

    // Associate contact with deal if both exist
    if (!contact) {
      // One more attempt: look up by order customer email
      const backupEmail = order?.customer?.email || order?.email || contactData.email;
      if (backupEmail) {
        try {
          const searchRes = await axios.post(
            `${hubspotClient.baseURL}/crm/v3/objects/contacts/search`,
            { filterGroups: [{ filters: [{ propertyName: 'email', operator: 'EQ', value: backupEmail }] }] },
            { headers: hubspotClient.headers }
          );
          const hit = Array.isArray(searchRes?.data?.results) ? searchRes.data.results[0] : null;
          if (hit && hit.id) {
            contact = hit;
            console.log(`👤 Fallback contact by order email: ${hit.id} - ${backupEmail}`);
          }
        } catch (_) {}
      }
    }
    if (contact && deal) {
      await hubspotClient.associateContactWithDeal(contact.id, deal.id);
    }

    // Create line items in HubSpot for PRODUCT items only (shipping items are handled as shipping cost)
    if (productLineItems && productLineItems.length > 0) {
      console.log(`📝 Creating ${productLineItems.length} product line items in HubSpot for deal ${deal.id}`);
      
      try {
        for (let i = 0; i < productLineItems.length; i++) {
          const shopifyLineItem = productLineItems[i];
          
          // Calculate ex-GST price for line item
          const grossLinePrice = parseFloat(shopifyLineItem.price) || 0;
          const exGstLinePrice = grossLinePrice / (1 + gstRate);
          const grossLineTotal = grossLinePrice * (parseInt(shopifyLineItem.quantity) || 1);
          const exGstLineTotal = exGstLinePrice * (parseInt(shopifyLineItem.quantity) || 1);
          
          // Transform Shopify line item to HubSpot format
          const hubspotLineItem = {
            name: shopifyLineItem.title || shopifyLineItem.name || `Item ${i + 1}`,
            quantity: parseInt(shopifyLineItem.quantity) || 1,
            price: exGstLinePrice, // Use ex-GST price
            amount: exGstLineTotal, // Use ex-GST total
            hs_sku: shopifyLineItem.sku || shopifyLineItem.variant_id || `SHOPIFY-${shopifyLineItem.id}`,
            description: `Shopify Product Line Item\nVariant ID: ${shopifyLineItem.variant_id || 'N/A'}\nProduct ID: ${shopifyLineItem.product_id || 'N/A'}${shopifyLineItem.variant_title ? `\nVariant: ${shopifyLineItem.variant_title}` : ''}\n\nPricing:\nPrice (ex-GST): $${exGstLinePrice.toFixed(2)}\nPrice (inc GST): $${grossLinePrice.toFixed(2)}\nTotal (ex-GST): $${exGstLineTotal.toFixed(2)}\nTotal (inc GST): $${grossLineTotal.toFixed(2)}`,
            // Custom properties for Shopify data
            shopify_line_item_id: shopifyLineItem.id,
            shopify_product_id: shopifyLineItem.product_id,
            shopify_variant_id: shopifyLineItem.variant_id,
            shopify_price_inc_gst: grossLinePrice,
            shopify_price_ex_gst: exGstLinePrice,
            shopify_total_inc_gst: grossLineTotal,
            shopify_total_ex_gst: exGstLineTotal
          };

          console.log(`📝 Creating product line item: ${hubspotLineItem.name} (Qty: ${hubspotLineItem.quantity}, Price: $${exGstLinePrice.toFixed(2)} ex-GST)`);

          // Create line item in HubSpot
          const createdLineItem = await hubspotClient.createLineItem(hubspotLineItem);
          
          // Associate line item with deal
          if (createdLineItem && createdLineItem.id) {
            await hubspotClient.associateLineItemWithDeal(createdLineItem.id, deal.id);
          }
        }
        
        console.log(`✅ Successfully created all ${productLineItems.length} product line items in HubSpot`);
        
      } catch (lineItemError) {
        console.error(`❌ Error creating line items (continuing with deal creation):`, lineItemError.message);
        // Don't throw error - line item creation failure shouldn't break the whole flow
      }
    } else {
      console.log(`ℹ️ No product line items found in Shopify order ${order.name}`);
    }

    // Log shipping handling summary
    if (shippingLineItems.length > 0 || totalShippingCost > 0) {
      console.log(`🚚 Shipping Summary:`);
      console.log(`   Shopify Shipping: $${shopifyShippingAmount.toFixed(2)}`);
      console.log(`   Shipping Line Items: $${shippingLineItemsTotal.toFixed(2)}`);
      console.log(`   Total Shipping Cost: $${totalShippingCost.toFixed(2)} (stored in deal.shopify_shipping_cost)`);
      console.log(`   Note: Shipping line items are NOT created as separate line items in HubSpot`);
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
    // Idempotency and duplicate checks
    if (wasDealRecentlyProcessed(dealId)) {
      console.log(`🛑 Skipping import for deal ${dealId}: recently processed`);
      return { order: null, skipped: true, reason: 'recently processed' };
    }
    const existingOrder = await findExistingShopifyOrderForDeal(dealId);
    if (existingOrder) {
      console.log(`🛑 Order already exists for deal ${dealId}: #${existingOrder?.name || existingOrder?.order_number || existingOrder?.id}`);
      markDealProcessed(dealId);
      return { order: existingOrder, skipped: true, reason: 'existing order' };
    }

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

    // Helper to split a full name into first/last parts while keeping initials intact
    const splitName = (fullName) => {
      if (!fullName || typeof fullName !== 'string') {
        return { first: null, last: null };
      }
      const trimmed = fullName.trim().replace(/\s+/g, ' ');
      if (trimmed.length === 0) return { first: null, last: null };
      const parts = trimmed.split(' ');
      if (parts.length === 1) {
        return { first: parts[0], last: null };
      }
      const last = parts.pop();
      const first = parts.join(' ');
      return { first, last };
    };

    // Determine company name for customer record
    const companyName = contactProps.company || 
                       deal.properties.dealname?.split(' - ')[0] || // Extract from deal name
                       'HubSpot Customer';

    // Attach to existing Shopify customer by email when possible to avoid validation
    let customer = null;
    const customerEmail = contactProps.email || `hubspot-${dealId}@placeholder.com`;
    const existingCustomer = await findShopifyCustomerByEmail(customerEmail);
    if (existingCustomer && existingCustomer.id) {
      console.log(`👤 Matched existing Shopify customer by email: ${customerEmail} → ID ${existingCustomer.id}`);
      customer = { id: existingCustomer.id };
    } else {
      // Create via order with minimal customer fields (omit phone to avoid uniqueness conflicts)
      customer = {
        first_name: firstName,
        last_name: lastName,
        email: customerEmail
      };
    }

    // Extract address information from multiple sources
    console.log(`🏠 Extracting address information...`);
    
    // Debug: Log all available invoice properties to see what address fields exist
    // Suppress verbose invoice property dumps
    
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
          // Prefer recipient company (bill-to) fields when present
          address1: props.hs_recipient_company_address || props.billing_address || props.billing_street || props.billing_address_line_1 || props.bill_to_address || props.bill_to_address1 || props.hs_sender_company_address || '',
          city: props.hs_recipient_company_city || props.billing_city || props.bill_to_city || props.billing_town || '',
          province: props.hs_recipient_company_state || props.billing_state || props.billing_province || props.bill_to_state || props.billing_region || '',
          country: props.hs_recipient_company_country || props.billing_country || props.bill_to_country || props.billing_country_code || 'Australia',
          zip: props.hs_recipient_company_zip || props.billing_zip || props.billing_postal_code || props.billing_postcode || props.bill_to_zip || '',
          company: props.hs_recipient_company || props.billing_company || props.bill_to_company || contactProps.company || ''
        },
        shipping: {
          // Prefer recipient shipping fields when present
          address1: props.hs_recipient_shipping_address || props.shipping_address || props.shipping_street || props.shipping_address_line_1 || props.ship_to_address || props.ship_to_address1 || props.ship_to_street || props.delivery_address || props.delivery_street || '',
          city: props.hs_recipient_shipping_city || props.shipping_city || props.ship_to_city || props.shipping_town || '',
          province: props.hs_recipient_shipping_state || props.shipping_state || props.shipping_province || props.ship_to_state || props.shipping_region || '',
          country: props.hs_recipient_shipping_country || props.shipping_country || props.ship_to_country || props.delivery_country || props.shipping_country_code || 'Australia',
          zip: props.hs_recipient_shipping_zip || props.shipping_zip || props.shipping_postal_code || props.shipping_postcode || props.ship_to_zip || props.delivery_zip || '',
          company: props.hs_recipient_shipping_company || props.shipping_company || props.ship_to_company || contactProps.company || ''
        }
      };
      
      const addressData = addressFields[type];
      // Candidate recipient name fields. For billing, HubSpot may store a bill-to name; for shipping, a recipient name.
      const recipientName = (type === 'shipping')
        ? (props.hs_recipient_shipping_name || props.shipping_name || props.ship_to_name || props.recipient_name || null)
        : (props.hs_recipient_company_name || props.billing_name || props.bill_to_name || props.recipient_billing_name || null);
      const parsed = splitName(recipientName || '');
      const addrFirst = parsed.first || firstName;
      const addrLast = parsed.last || lastName;
      
      // Only return if we have at least address1 or city
      if (addressData.address1 || addressData.city) {
        return {
          first_name: addrFirst,
          last_name: addrLast,
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
    let invoiceShippingAddress = getInvoiceAddress('shipping');
    let invoiceBillingAddress = getInvoiceAddress('billing');

    // If invoice addresses are missing, try associated quote(s)
    if ((!invoiceShippingAddress || !invoiceBillingAddress) && invoiceInfo) {
      try {
        // Prefer direct associations from invoice if present
        let quoteIds = [];
        if (invoiceInfo.associations && invoiceInfo.associations.quotes && Array.isArray(invoiceInfo.associations.quotes.results)) {
          quoteIds = invoiceInfo.associations.quotes.results.map(r => r.id).filter(Boolean);
        }
        // If not present on invoice, pull quotes associated with the deal
        if (quoteIds.length === 0) {
          const quotes = await hubspotClient.getAssociatedQuotes(dealId);
          quoteIds = quotes.map(q => q.id);
        }

        if (quoteIds.length > 0) {
          const quote = await hubspotClient.getQuote(quoteIds[0]);
          if (quote && quote.properties) {
            const qp = quote.properties;
            const mapQuoteAddr = (type) => {
              const qAddr = type === 'shipping' ? {
                address1: qp.shipping_address || qp.shipping_street || qp.ship_to_address || qp.ship_to_street || qp.address || qp.address_line_1 || qp.address1 || '',
                city: qp.shipping_city || qp.ship_to_city || qp.city || '',
                province: qp.shipping_state || qp.shipping_province || qp.ship_to_state || qp.state || '',
                country: qp.shipping_country || qp.ship_to_country || qp.country || 'Australia',
                zip: qp.shipping_zip || qp.shipping_postal_code || qp.ship_to_zip || qp.postal_code || qp.postcode || qp.zip || '',
                company: qp.shipping_company || qp.ship_to_company || contactProps.company || ''
              } : {
                address1: qp.billing_address || qp.billing_street || qp.bill_to_address || qp.bill_to_street || qp.address || qp.address_line_1 || qp.address1 || '',
                city: qp.billing_city || qp.bill_to_city || qp.city || '',
                province: qp.billing_state || qp.billing_province || qp.bill_to_state || qp.state || '',
                country: qp.billing_country || qp.bill_to_country || qp.country || 'Australia',
                zip: qp.billing_zip || qp.billing_postal_code || qp.bill_to_zip || qp.postal_code || qp.postcode || qp.zip || '',
                company: qp.billing_company || qp.bill_to_company || contactProps.company || ''
              };
              if (qAddr.address1 || qAddr.city) {
                return {
                  first_name: firstName,
                  last_name: lastName,
                  company: qAddr.company,
                  address1: qAddr.address1,
                  city: qAddr.city,
                  province: qAddr.province,
                  country: qAddr.country,
                  zip: qAddr.zip,
                  phone: formattedPhone
                };
              }
              return null;
            };

            if (!invoiceShippingAddress) invoiceShippingAddress = mapQuoteAddr('shipping');
            if (!invoiceBillingAddress) invoiceBillingAddress = mapQuoteAddr('billing');
          }
        }
      } catch (quoteErr) {
        console.log(`ℹ️ Quote-based address extraction not available:`, quoteErr.message);
      }
    }
    const contactAddress = getContactAddress();
    // Company address (associated company) fallback
    let companyAddress = null;
    try {
      const companies = await hubspotClient.getAssociatedCompanies(dealId);
      if (Array.isArray(companies) && companies.length > 0) {
        const cp = companies[0].properties || companies[0];
        const address1 = cp.address || cp.address_line_1 || cp.street || cp.address1 || '';
        const city = cp.city || '';
        const province = cp.state || cp.province || '';
        const zip = cp.zip || cp.postal_code || cp.postcode || '';
        const country = cp.country || 'Australia';
        const company = cp.name || contactProps.company || '';
        if (address1 || city) {
          companyAddress = {
            first_name: firstName,
            last_name: lastName,
            company,
            address1,
            city,
            province,
            country,
            zip,
            phone: formattedPhone
          };
        }
      }
    } catch (e) {
      console.log(`ℹ️ Company address fallback not available:`, e.message);
    }
    
    console.log(`🏠 Address extraction results:`);
    console.log(`   🏢 Deal shipping:`, dealShippingAddress);
    console.log(`   🏢 Deal billing:`, dealBillingAddress);
    console.log(`   📦 Invoice shipping:`, invoiceShippingAddress);
    console.log(`   💰 Invoice billing:`, invoiceBillingAddress);
    console.log(`   👤 Contact address:`, contactAddress);
    console.log(`   🏢 Company address:`, companyAddress);
    
    // Build final addresses with proper fallback logic
    // Priority: Deal address → Invoice/Quote address → Company address → Contact address → Manual entry
    // IMPORTANT: If shipping isn't available, fall back to billing address
    let shippingAddress = dealShippingAddress || invoiceShippingAddress || dealBillingAddress || 
                         invoiceBillingAddress || companyAddress || contactAddress;
    let billingAddress = dealBillingAddress || invoiceBillingAddress || companyAddress || contactAddress;
    
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
      // Stefan Locasto / ExposurePack - Deal ID: 40735781445
      '40735781445': {
        billing: {
          company: 'ExposurePack',
          address1: '3 hudson st',
          city: 'Caulfield north',
          province: 'VIC',
          zip: '3161'
        },
        shipping: {
          company: 'ExposurePack',
          address1: '2 Bataba St',
          city: 'Moorabbin',
          province: 'VIC',
          zip: '3189'
        }
      },
      // Email based addresses
      'admin@thehoi.com.au': {
        company: 'The hoi polloi', 
        address1: '234-226 flinders street',
        city: 'Townsville',
        province: 'QLD',
        zip: '4812'
      },
      'stefan@exposurepack.com.au': {
        billing: {
          company: 'ExposurePack',
          address1: '3 hudson st',
          city: 'Caulfield north',
          province: 'VIC',
          zip: '3161'
        },
        shipping: {
          company: 'ExposurePack',
          address1: '2 Bataba St',
          city: 'Moorabbin',
          province: 'VIC',
          zip: '3189'
        }
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
      
      // Check if this is the new structure with separate billing/shipping
      if (knownAddress.billing && knownAddress.shipping) {
        console.log(`📍 Found separate billing and shipping addresses`);
        
        const manualBillingAddress = {
          first_name: firstName,
          last_name: lastName,
          company: knownAddress.billing.company || companyName,
          address1: knownAddress.billing.address1,
          city: knownAddress.billing.city,
          province: knownAddress.billing.province,
          country: 'Australia',
          zip: knownAddress.billing.zip,
          phone: formattedPhone
        };
        
        const manualShippingAddress = {
          first_name: firstName,
          last_name: lastName,
          company: knownAddress.shipping.company || companyName,
          address1: knownAddress.shipping.address1,
          city: knownAddress.shipping.city,
          province: knownAddress.shipping.province,
          country: 'Australia',
          zip: knownAddress.shipping.zip,
          phone: formattedPhone
        };
        
        billingAddress = manualBillingAddress;
        shippingAddress = manualShippingAddress;
        
        console.log(`🔧 Manual billing address applied:`, manualBillingAddress);
        console.log(`🔧 Manual shipping address applied:`, manualShippingAddress);
        
      } else {
        // Legacy format - use same address for both billing and shipping
        console.log(`📍 Found legacy single address format`);
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
        console.log(`🔧 Manual address applied (legacy format):`, manualAddress);
      }
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
      if (address === companyAddress) return 'Company';
      if (address === contactAddress) return 'Contact';
      if (knownAddress && knownAddress.billing && knownAddress.shipping) {
        return isShipping ? 'Manual Shipping Override' : 'Manual Billing Override';
      }
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
        email: customerEmail,
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

    // If addresses are effectively the same, propagate missing fields both ways
    const normalizeForCompare = (addr) => {
      if (!addr) return '';
      const parts = [addr.address1, addr.city, addr.province, addr.zip, addr.country]
        .filter(Boolean)
        .map(s => String(s).toLowerCase().replace(/[^a-z0-9]/g, ''));
      return parts.join('|');
    };

    if (shippingAddress && billingAddress) {
      const same = normalizeForCompare(shippingAddress) === normalizeForCompare(billingAddress);
      if (same) {
        const fieldsToSync = ['company', 'phone', 'address1', 'city', 'province', 'country', 'zip'];
        fieldsToSync.forEach((f) => {
          if (!shippingAddress[f] && billingAddress[f]) shippingAddress[f] = billingAddress[f];
          if (!billingAddress[f] && shippingAddress[f]) billingAddress[f] = shippingAddress[f];
        });
      }
      // Always ensure shipping has company if billing has one
      if (!shippingAddress.company && billingAddress.company) {
        shippingAddress.company = billingAddress.company;
      }
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

    // Save HubSpot deal notes into Shopify metafield custom.notes (JSON)
    try {
      // Attempt to gather notes from available objects: deal description, invoice/quote notes, contact/company
      const notes = [];
      const pushNote = (source, text) => {
        const t = (text || '').toString().trim();
        if (t.length > 0) notes.push({ source, text: t });
      };

      // Deal description
      pushNote('deal.description', deal?.properties?.description);

      // HubSpot associated notes (CRM notes)
      try {
        const assocRes = await axios.get(
          `${hubspotClient.baseURL}/crm/v3/objects/deals/${dealId}/associations/notes`,
          { headers: hubspotClient.headers, timeout: 30000 }
        );
        const noteIds = Array.isArray(assocRes?.data?.results)
          ? assocRes.data.results.map(r => r.id)
          : [];
        const limited = noteIds.slice(0, 10); // cap to 10 notes
        for (const nid of limited) {
          try {
            const noteRes = await axios.get(
              `${hubspotClient.baseURL}/crm/v3/objects/notes/${nid}`,
              {
                headers: hubspotClient.headers,
                params: { properties: ['hs_note_body','hs_createdate','hs_lastmodifieddate','hubspot_owner_id'].join(',') },
                timeout: 30000
              }
            );
            const np = noteRes?.data?.properties || {};
            pushNote('hubspot.note', np.hs_note_body);
          } catch (nrErr) {}
        }
      } catch (assocErr) {
        // ignore
      }

      // Contact properties that could be note-like
      if (contacts && contacts.length > 0) {
        const cp = contacts[0]?.properties || {};
        pushNote('contact.address', [cp.address, cp.city, cp.state, cp.zip, cp.country].filter(Boolean).join(', '));
      }

      // Company notes via invoice association (recipient/company address already captured but include label)
      if (invoiceInfo && invoiceInfo.properties) {
        const ip = invoiceInfo.properties;
        const receiverAddr = [ip.hs_recipient_company_address, ip.hs_recipient_company_city, ip.hs_recipient_company_state, ip.hs_recipient_company_zip].filter(Boolean).join(', ');
        pushNote('invoice.recipient_address', receiverAddr);
        if (ip.hs_recipient_shipping_name) pushNote('invoice.recipient_name', ip.hs_recipient_shipping_name);
      }

      // Render as readable multi-line text (definition expects multi_line_text_field)
      const lines = [];
      lines.push(`Deal: ${dealName} (ID ${dealId})`);
      notes.forEach((n, i) => lines.push(`${i + 1}. [${n.source}] ${n.text}`));
      const notesPayload = lines.join('\n');

      await metafieldManager.setMetafield(
        orderGID,
        'custom',
        'notes',
        notesPayload,
        'multi_line_text_field'
      );
      console.log(`🗒️ Saved HubSpot notes to metafield custom.notes (${notes.length} items)`);
    } catch (notesErr) {
      console.warn('⚠️ Failed to save HubSpot notes to metafield:', notesErr.message);
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

// ==================================================
// Idempotency helpers to prevent duplicate order loops
// ==================================================
const processedHubspotDeals = new Map(); // dealId -> timestamp
const processedShopifyOrders = new Map(); // orderId -> timestamp
const processedShopifyCustomers = new Map(); // customerId -> timestamp
const processedHubspotContacts = new Map(); // contactId -> timestamp

// In-flight concurrency locks to prevent simultaneous processing for same deal
const processingDeals = new Set(); // dealId currently being processed

const acquireDealLock = (dealId) => {
  const key = String(dealId);
  if (processingDeals.has(key)) return false;
  processingDeals.add(key);
  return true;
};

const releaseDealLock = (dealId) => {
  const key = String(dealId);
  if (processingDeals.has(key)) processingDeals.delete(key);
};

const wasDealRecentlyProcessed = (dealId, ttlMs = 10 * 60 * 1000) => {
  try {
    const ts = processedHubspotDeals.get(String(dealId));
    return !!ts && (Date.now() - ts) < ttlMs;
  } catch (_) {
    return false;
  }
};

const markDealProcessed = (dealId) => {
  try {
    processedHubspotDeals.set(String(dealId), Date.now());
  } catch (_) {}
};

const wasOrderRecentlyProcessed = (orderId, ttlMs = 10 * 60 * 1000) => {
  try {
    const ts = processedShopifyOrders.get(String(orderId));
    return !!ts && (Date.now() - ts) < ttlMs;
  } catch (_) {
    return false;
  }
};

const markOrderProcessed = (orderId) => {
  try {
    processedShopifyOrders.set(String(orderId), Date.now());
  } catch (_) {}
};

const wasCustomerRecentlyProcessed = (customerId, ttlMs = 10 * 60 * 1000) => {
  try {
    const ts = processedShopifyCustomers.get(String(customerId));
    return !!ts && (Date.now() - ts) < ttlMs;
  } catch (_) {
    return false;
  }
};

const markCustomerProcessed = (customerId) => {
  try {
    processedShopifyCustomers.set(String(customerId), Date.now());
  } catch (_) {}
};

const wasHubspotContactRecentlyProcessed = (contactId, ttlMs = 10 * 60 * 1000) => {
  try {
    const ts = processedHubspotContacts.get(String(contactId));
    return !!ts && (Date.now() - ts) < ttlMs;
  } catch (_) {
    return false;
  }
};

const markHubspotContactProcessed = (contactId) => {
  try {
    processedHubspotContacts.set(String(contactId), Date.now());
  } catch (_) {}
};

// Periodically purge old processed entries (every 15 minutes)
setInterval(() => {
  try {
    const now = Date.now();
    for (const [dealId, ts] of processedHubspotDeals.entries()) {
      if ((now - ts) > (30 * 60 * 1000)) { // 30 minutes TTL for cleanup
        processedHubspotDeals.delete(dealId);
      }
    }
    for (const [orderId, ots] of processedShopifyOrders.entries()) {
      if ((now - ots) > (30 * 60 * 1000)) {
        processedShopifyOrders.delete(orderId);
      }
    }
    for (const [customerId, cts] of processedShopifyCustomers.entries()) {
      if ((now - cts) > (30 * 60 * 1000)) {
        processedShopifyCustomers.delete(customerId);
      }
    }
  } catch (_) {}
}, 15 * 60 * 1000);

// Quick lookup to see if we've already created a Shopify order for a HubSpot deal
async function findExistingShopifyOrderForDeal(dealId) {
  try {
    const res = await restClient.get(`/orders.json?status=any&limit=50&fields=id,name,tags,order_number,note,note_attributes`);
    const orders = Array.isArray(res?.orders) ? res.orders : [];
    const dealTag = `hubspot-deal-${dealId}`.toLowerCase();
    const match = orders.find(o => {
      const tags = (Array.isArray(o.tags) ? o.tags.join(',') : (o.tags || '')).toLowerCase();
      const tagHit = tags.includes(dealTag);
      const noteAttrs = Array.isArray(o.note_attributes) ? o.note_attributes : [];
      const attrHit = noteAttrs.some(na => (String(na.name || '').toLowerCase() === 'hubspot_deal_id') && String(na.value) === String(dealId));
      return tagHit || attrHit;
    });
    return match || null;
  } catch (err) {
    console.warn(`⚠️ Failed to search existing Shopify orders for deal ${dealId}:`, err.message);
    return null;
  }
}

// Find a Shopify customer by email (returns first match or null)
async function findShopifyCustomerByEmail(email) {
  if (!email) return null;
  try {
    const query = `email:${email}`;
    const res = await restClient.get(`/customers/search.json?query=${encodeURIComponent(query)}`);
    const customers = Array.isArray(res?.customers) ? res.customers : [];
    return customers.length > 0 ? customers[0] : null;
  } catch (err) {
    console.warn(`⚠️ Failed to search Shopify customer by email ${email}:`, err.message);
    return null;
  }
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
        analytics: ["/analytics-data"],
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
    if (LOG_VERBOSE) {
      const { orderGID, key, type = "single_line_text_field", namespace = "custom" } = req.body;
      console.log("📝 Incoming /metafields request:", { orderGID, key, type, namespace });
    }

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
      if (LOG_VERBOSE) console.log(`🗑️ Deleting metafield: ${namespace}.${key} for order ${orderGID}`);
      
      const existingMetafield = await metafieldManager.findMetafield(orderGID, namespace, key);
      
      if (!existingMetafield) {
        if (LOG_VERBOSE) console.log("ℹ️ No metafield found to delete");
        return res.json({ 
          success: true, 
          deleted: false, 
          message: "No metafield exists to delete" 
        });
      }

      const deletedMetafield = await metafieldManager.deleteMetafield(existingMetafield.id);
      console.log(`✅ Metafield deleted: ${deletedMetafield.id}`);
      
      return res.json({ 
        success: true, 
        deleted: true, 
        deletedId: deletedMetafield.id 
      });
    }

    // Handle creation/update
    if (LOG_VERBOSE) console.log(`💾 Setting metafield: ${namespace}.${key}`);
    const metafield = await metafieldManager.setMetafield(orderGID, namespace, key, value, type);
    
    console.log(`✅ Metafield set: ${metafield.id}`);
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
 * Soft delete an order (mark as deleted via metafield). Does not touch HubSpot.
 */
app.post("/orders/:id/delete", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const legacyId = id.replace(/\D/g, '');
    const orderGID = `gid://shopify/Order/${legacyId}`;

    // 1) Mark as deleted via metafield
    await metafieldManager.setMetafield(orderGID, "custom", "deleted", "true", "single_line_text_field");

    res.json({ success: true, id: legacyId });
  } catch (error) {
    handleError(error, res, "Failed to delete order");
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
  console.log("🚚 Creating fulfillment via Shopify REST API (Fulfillment Orders API)");

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

    // Pre-check: Verify order exists and is fulfillable
    console.log(`🔍 Fetching order details for pre-check...`);
    try {
      const orderCheckResponse = await restClient.get(`/orders/${numericOrderId}.json`);
      const orderDetails = orderCheckResponse.order;
      console.log(`📋 Order Status Check:`);
      console.log(`   💰 Financial Status: ${orderDetails.financial_status}`);
      console.log(`   📦 Fulfillment Status: ${orderDetails.fulfillment_status || 'unfulfilled'}`);
      if (orderDetails.financial_status?.toLowerCase() !== 'paid') {
        throw new Error(`Order must be paid before fulfillment. Current status: ${orderDetails.financial_status}`);
      }
      if (orderDetails.fulfillment_status?.toLowerCase() === 'fulfilled') {
        throw new Error(`Order is already fully fulfilled.`);
      }
    } catch (orderFetchError) {
      console.error(`⚠️ Could not fetch order details for pre-check:`, orderFetchError.message);
    }

    // Use Fulfillment Orders API (required on latest versions)
    console.log(`📦 Fetching fulfillment orders for order ${numericOrderId}...`);
    const foRes = await restClient.get(`/orders/${numericOrderId}/fulfillment_orders.json`);
    const fulfillmentOrders = foRes.fulfillment_orders || [];
    if (fulfillmentOrders.length === 0) {
      throw new Error('No fulfillment orders found for this order');
    }

    // Build line_items_by_fulfillment_order for all remaining quantities
    const lineItemsByFO = fulfillmentOrders.map(fo => {
      const items = (fo.line_items || []).map(li => ({
        id: li.id,
        quantity: li.remaining_quantity ?? li.fulfillable_quantity ?? li.quantity
      })).filter(li => (li.quantity || 0) > 0);
      return {
        fulfillment_order_id: fo.id,
        fulfillment_order_line_items: items
      };
    }).filter(group => group.fulfillment_order_line_items.length > 0);

    if (lineItemsByFO.length === 0) {
      return res.status(400).json({ success: false, error: 'Nothing to fulfill (no remaining quantities)' });
    }

    const fulfillmentPayload = {
      fulfillment: {
        notify_customer: notifyCustomer,
        tracking_info: {
          number: trackingNumber,
          company: trackingCompany
        },
        line_items_by_fulfillment_order: lineItemsByFO
      }
    };

    console.log(`🔍 Making Shopify REST API call:`);
    console.log(`📍 URL: /fulfillments.json`);
    console.log(`📋 Final fulfillment data:`, JSON.stringify(fulfillmentPayload, null, 2));

    // Create fulfillment using Shopify REST API (FO API)
    const fulfillmentResponse = await restClient.post(
      `/fulfillments.json`,
      fulfillmentPayload
    );

    console.log(`✅ Fulfillment created successfully:`, fulfillmentResponse);

    res.json({
      success: true,
      fulfillment: fulfillmentResponse,
      message: "Fulfillment created successfully via Fulfillment Orders API",
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
    if (LOG_VERBOSE) console.log("📋 Fetching orders with enhanced pagination...");

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
              metafields(first: 30, namespace: "custom") {
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
      if (LOG_VERBOSE) console.log("🔄 Using pagination to fetch all orders...");
      orders = await graphqlClient.queryWithPagination(ordersQuery, variables, pageSize);
    } else {
      const data = await graphqlClient.query(ordersQuery, variables);
      orders = data.data.orders.edges;
    }

    // Fetch note_attributes for all orders via REST API (for business_name, customer_name, etc.)
    if (LOG_VERBOSE) console.log("📋 Fetching note_attributes for all orders...");
    let restOrdersMap = {};
    try {
      const restOrdersRes = await restClient.get(`/orders.json?limit=250&status=any&fields=id,note_attributes`);
      restOrdersRes.orders.forEach((order) => {
        const noteAttributes = {};
        order.note_attributes.forEach((na) => {
          noteAttributes[na.name] = na.value;
        });
        restOrdersMap[order.id] = noteAttributes;
      });
      if (LOG_VERBOSE) console.log(`✅ Fetched note_attributes for ${Object.keys(restOrdersMap).length} orders`);
    } catch (restError) {
      if (LOG_VERBOSE) console.warn("⚠️ Could not fetch note_attributes via REST:", restError.message);
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
        deleted: metafields.deleted === 'true' || metafields.deleted === true,
        // Smart display names (prioritizes custom attributes)
        display_business_name: businessName,
        display_customer_name: customerName,
        line_items: lineItems,
      };
    });

    // Fetch tracking details (order_status_url and fulfillments with shipment_status)
    // only for orders that appear dispatched, to minimise REST calls
    let restTrackMap = {};
    try {
      const dispatchedLegacyIds = transformedOrders
        .filter(o => o.metafields?.ready_for_dispatch_date_time)
        .map(o => o.legacy_id)
        .filter(Boolean);

      if (dispatchedLegacyIds.length) {
        // Shopify REST supports ids param (comma-separated). If too many, chunk later if needed.
        const idsParam = dispatchedLegacyIds.join(',');
        const restForTracking = await restClient.get(`/orders.json?status=any&ids=${idsParam}`);
        (restForTracking.orders || []).forEach((o) => {
          restTrackMap[o.id] = {
            order_status_url: o.order_status_url || null,
            fulfillments: (o.fulfillments || []).map((f) => ({
              id: f.id,
              tracking_company: f.tracking_company || null,
              tracking_number: f.tracking_number || (Array.isArray(f.tracking_numbers) ? f.tracking_numbers[0] : null),
              tracking_numbers: Array.isArray(f.tracking_numbers) ? f.tracking_numbers : (f.tracking_number ? [f.tracking_number] : []),
              tracking_url: f.tracking_url || (Array.isArray(f.tracking_urls) ? f.tracking_urls[0] : null),
              tracking_urls: Array.isArray(f.tracking_urls) ? f.tracking_urls : (f.tracking_url ? [f.tracking_url] : []),
              shipment_status: f.shipment_status || null,
              status: f.status || null,
            })),
          };
        });
      }
    } catch (e) {
      if (LOG_VERBOSE) console.warn('⚠️ Could not fetch tracking details for dispatched orders:', e.message);
    }

    const mergedOrders = transformedOrders.map((o) => {
      const track = restTrackMap[o.legacy_id] || {};
      return {
        ...o,
        order_status_url: track.order_status_url || null,
        fulfillments: track.fulfillments || [],
      };
    });

    const filtered = (mergedOrders || transformedOrders).filter(o => !o.deleted);
    const response = {
      orders: filtered,
      count: filtered.length,
      pagination: shouldPaginate ? {
        total_fetched: transformedOrders.length,
        method: "full_pagination"
      } : {
        page_size: pageSize,
        has_more: false // Would need pageInfo from single query to determine
      }
    };

    console.log(`🟢 ${response.count}/${transformedOrders.length} orders loaded.`);
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
    
    if (LOG_VERBOSE) console.log(`🔍 Fetching detailed order: ${legacyId}`);

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
      if (LOG_VERBOSE) console.log(`✅ Fetched note_attributes for order ${legacyId}:`, Object.keys(noteAttributes));
    } catch (restError) {
      if (LOG_VERBOSE) console.warn("⚠️ Could not fetch note_attributes via REST:", restError.message);
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

    console.log(`🟢 Order loaded: ${node.name} (${legacyId}).`);
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
    if (LOG_VERBOSE) console.log(`🔄 REST fallback: fetching order ${id}`);
    
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
 * Update order shipping address
 */
app.put("/orders/:id/shipping-address", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const legacyId = id.replace(/\D/g, ''); // Extract numeric ID
    const { shipping_address } = req.body;
    
    if (!shipping_address) {
      return res.status(400).json({ 
        error: "shipping_address is required",
        message: "Please provide shipping address data to update"
      });
    }
    
    console.log(`📮 Updating shipping address for order: ${legacyId}`);
    console.log(`📮 New address data:`, shipping_address);
    
    // Update order via Shopify REST API
    const updateData = {
      order: {
        id: parseInt(legacyId),
        shipping_address: {
          first_name: shipping_address.first_name || '',
          last_name: shipping_address.last_name || '',
          name: shipping_address.name || `${shipping_address.first_name || ''} ${shipping_address.last_name || ''}`.trim(),
          company: shipping_address.company || '',
          address1: shipping_address.address1 || '',
          address2: shipping_address.address2 || '',
          city: shipping_address.city || '',
          province: shipping_address.province || '',
          province_code: shipping_address.province_code || '',
          country: shipping_address.country || '',
          country_code: shipping_address.country_code || '',
          zip: shipping_address.zip || '',
          phone: shipping_address.phone || ''
        }
      }
    };
    
    // Use REST API to update the order
    const updatedOrder = await restClient.put(`/orders/${legacyId}.json`, updateData);
    
    console.log(`✅ Successfully updated shipping address for order ${legacyId}`);
    
    res.json({
      success: true,
      message: "Shipping address updated successfully",
      order: updatedOrder.order,
      shipping_address: updatedOrder.order.shipping_address
    });
    
  } catch (error) {
    console.error("❌ Error updating shipping address:", error);
    console.error("❌ Error details:", error.response?.data || error.message);
    
    const statusCode = error.response?.status || 500;
    const errorMessage = error.response?.data?.errors || error.message || "Failed to update shipping address";
    
    res.status(statusCode).json({
      error: "Failed to update shipping address",
      message: errorMessage,
      details: error.response?.data
    });
  }
});

// Fetch a single customer by ID (returns tags among other fields)
app.get("/rest/customers/:id", async (req, res) => {
  try {
    const { id } = req.params;
    if (!id) {
      return res.status(400).json({ error: "Missing customer id" });
    }
    const normalizedId = String(id).replace(/\D+/g, "");
    console.log(`🔄 REST: fetching customer ${normalizedId}`);
    const customerData = await restClient.get(`/customers/${normalizedId}.json`);
    res.json(customerData);
  } catch (error) {
    handleError(error, res, "REST customer fetch failed");
  }
});

// Search customer by email (uses Admin REST customers/search)
app.get("/rest/customers/search", async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) {
      return res.status(400).json({ error: "Missing email query param" });
    }
    const query = `email:${email}`;
    console.log(`🔄 REST: searching customer by email: ${email}`);
    const searchData = await restClient.get(`/customers/search.json?query=${encodeURIComponent(query)}`);
    // Return first match if exists
    const customer = Array.isArray(searchData?.customers) && searchData.customers.length > 0 ? searchData.customers[0] : null;
    res.json({ customer, count: searchData?.customers?.length || 0 });
  } catch (error) {
    handleError(error, res, "REST customer search failed");
  }
});

// Add or replace a membership tag (bronze/silver/gold) on a customer
app.post("/rest/customers/:id/tags", async (req, res) => {
  try {
    const { id } = req.params;
    const { tier } = req.body || {};
    if (!id || !tier) {
      return res.status(400).json({ error: "Missing id or tier" });
    }
    const normalizedId = String(id).replace(/\D+/g, "");
    const allowed = ["bronze", "silver", "gold"];
    const tierLower = String(tier).toLowerCase();
    if (!allowed.includes(tierLower)) {
      return res.status(400).json({ error: "Invalid tier" });
    }

    console.log(`🏷️ Updating customer ${normalizedId} tags → ${tierLower}`);

    // Get current tags
    const current = await restClient.get(`/customers/${normalizedId}.json`);
    const existingTags = (current?.customer?.tags || "").split(",").map(t => t.trim()).filter(Boolean);

    // Remove other tier tags and add the requested one
    const filtered = existingTags.filter(t => !allowed.includes(t.toLowerCase()));
    if (!filtered.map(t => t.toLowerCase()).includes(tierLower)) filtered.push(tierLower);

    const payload = {
      customer: {
        id: Number(normalizedId),
        tags: filtered.join(", ")
      }
    };

    const updateRes = await restClient.put(`/customers/${normalizedId}.json`, payload);
    res.json({ ok: true, updated: updateRes?.customer?.tags || filtered.join(", ") });
  } catch (error) {
    handleError(error, res, "REST customer tag update failed");
  }
});

// Same functionality without /rest prefix for storefront path compatibility
app.get("/customers/search", async (req, res) => {
  try {
    const { email } = req.query;
    if (!email) return res.status(400).json({ error: "Missing email query param" });
    const query = `email:${email}`;
    console.log(`🔄 (no-rest) searching customer by email: ${email}`);
    const searchData = await restClient.get(`/customers/search.json?query=${encodeURIComponent(query)}`);
    const customer = Array.isArray(searchData?.customers) && searchData.customers.length > 0 ? searchData.customers[0] : null;
    res.json({ customer, count: searchData?.customers?.length || 0 });
  } catch (error) {
    handleError(error, res, "(no-rest) customer search failed");
  }
});

app.post("/customers/:id/tags", async (req, res) => {
  try {
    const { id } = req.params; const { tier } = req.body || {};
    if (!id || !tier) return res.status(400).json({ error: "Missing id or tier" });
    const normalizedId = String(id).replace(/\D+/g, "");
    const allowed = ["bronze", "silver", "gold"]; const t = String(tier).toLowerCase();
    if (!allowed.includes(t)) return res.status(400).json({ error: "Invalid tier" });
    const current = await restClient.get(`/customers/${normalizedId}.json`);
    const existingTags = (current?.customer?.tags || "").split(",").map(s=>s.trim()).filter(Boolean);
    const filtered = existingTags.filter(x => !allowed.includes(x.toLowerCase()));
    if (!filtered.map(x=>x.toLowerCase()).includes(t)) filtered.push(t);
    const payload = { customer: { id: Number(normalizedId), tags: filtered.join(", ") } };
    const updateRes = await restClient.put(`/customers/${normalizedId}.json`, payload);
    res.json({ ok: true, updated: updateRes?.customer?.tags || filtered.join(", ") });
  } catch (error) {
    handleError(error, res, "(no-rest) customer tag update failed");
  }
});

/**
 * Analytics data endpoint - serves HubSpot deals + Shopify fallback data
 */
app.all("/analytics-data", async (req, res) => {
  const startTime = Date.now();
  
  try {
    console.log("📊 Analytics data request received", req.method, req.query);
    
    // Lightweight ops routed through the known path to avoid CORS/404 issues
    if (req.method === 'GET' && req.query.op === 'searchCustomer') {
      const email = req.query.email;
      if (!email) return res.status(400).json({ error: 'Missing email' });
      try {
        const query = `email:${email}`;
        const searchData = await restClient.get(`/customers/search.json?query=${encodeURIComponent(query)}`);
        const customer = Array.isArray(searchData?.customers) && searchData.customers.length > 0 ? searchData.customers[0] : null;
        return res.json({ customer, count: searchData?.customers?.length || 0 });
      } catch (err) {
        return handleError(err, res, 'analytics-data searchCustomer failed');
      }
    }
    if (req.method === 'POST' && req.query.op === 'tagCustomer') {
      const { id, tier } = req.body || {};
      if (!id || !tier) return res.status(400).json({ error: 'Missing id or tier' });
      try {
        const normalizedId = String(id).replace(/\D+/g, "");
        const allowed = ["bronze","silver","gold"]; const t = String(tier).toLowerCase();
        if (!allowed.includes(t)) return res.status(400).json({ error: 'Invalid tier' });
        const current = await restClient.get(`/customers/${normalizedId}.json`);
        const existingTags = (current?.customer?.tags || "").split(",").map(s=>s.trim()).filter(Boolean);
        const filtered = existingTags.filter(x=>!allowed.includes(x.toLowerCase()));
        if (!filtered.map(x=>x.toLowerCase()).includes(t)) filtered.push(t);
        const payload = { customer: { id: Number(normalizedId), tags: filtered.join(", ") } };
        const updateRes = await restClient.put(`/customers/${normalizedId}.json`, payload);
        return res.json({ ok:true, updated: updateRes?.customer?.tags || filtered.join(", ") });
      } catch (err) {
        return handleError(err, res, 'analytics-data tagCustomer failed');
      }
    }

    const { startDate, endDate, source } = req.query;
    
    let dateRange = null;
    if (startDate && endDate) {
      dateRange = { startDate, endDate };
      console.log(`📅 Date range filter: ${startDate} to ${endDate}`);
    } else {
      // Default to the last N months (6) if no explicit range provided
      const monthsParam = parseInt(req.query.months || '6');
      if (!Number.isNaN(monthsParam) && monthsParam > 0) {
        const end = new Date();
        const start = new Date();
        start.setMonth(start.getMonth() - monthsParam);
        dateRange = {
          startDate: start.toISOString().slice(0, 10),
          endDate: end.toISOString().slice(0, 10)
        };
        console.log(`📅 Default HubSpot window (months=${monthsParam}): ${dateRange.startDate} → ${dateRange.endDate}`);
      }
    }
    
    let analyticsData = {
      source: 'fallback', // Default fallback
      orders: [],
      total_count: 0,
      hubspot_available: !!hubspotClient
    };
    
    // Try HubSpot first if available and not explicitly requesting fallback
    if (hubspotClient && source !== 'shopify') {
      try {
        console.log("🎯 Attempting to fetch HubSpot deals data...");
        
        const hubspotDealsRaw = await hubspotClient.getDealsForAnalytics(dateRange);

        // Performance controls (defaults: months=6 handled above, max=250 deals, enrich=off)
        const maxDeals = Math.max(1, parseInt(req.query.max || '250'));
        const enrichParam = String(req.query.enrich || '0').toLowerCase();
        const enrich = enrichParam === '1' || enrichParam === 'true';
        const hubspotDeals = (hubspotDealsRaw || []).slice(0, maxDeals);

        // Optional enrichment only when explicitly enabled
        const contactsByDealId = {};
        const companiesByDealId = {};
        if (enrich) {
          for (const d of hubspotDeals) {
            try {
              const contacts = await hubspotClient.getAssociatedContacts(d.id);
              if (Array.isArray(contacts) && contacts.length > 0) {
                contactsByDealId[d.id] = contacts[0];
              }
            } catch (e) {}
            try {
              const companies = await hubspotClient.getAssociatedCompanies(d.id);
              if (Array.isArray(companies) && companies.length > 0) {
                companiesByDealId[d.id] = companies[0];
              }
            } catch (e) {}
          }
        }

        // Transform HubSpot deals to Shopify order format for compatibility (lite by default)
        const transformedOrders = hubspotDeals.map(deal => {
          const props = deal.properties;
          // Convert HubSpot millisecond timestamps to ISO if needed
          const toISO = (v) => v ? (isNaN(Number(v)) ? v : new Date(Number(v)).toISOString()) : null;
          const createdISO = toISO(props.closedate || props.createdate || deal.createdAt);
          const closedISO = toISO(props.closedate);
          
          const contact = enrich ? contactsByDealId[deal.id] : null;
          const company = enrich ? companiesByDealId[deal.id] : null;
          const cprops = contact?.properties || {};
          const contactEmail = cprops.email || null;
          const contactFirst = cprops.firstname || '';
          const contactLast = cprops.lastname || '';
          const contactFullName = `${contactFirst} ${contactLast}`.trim() || null;
          const contactCompany = cprops.company || company?.properties?.name || null;

          return {
            id: props.shopify_order_id || deal.id,
            name: props.shopify_order_number || props.dealname,
            // Use closed date primarily for chart bucketing (matches HubSpot "Close Date")
            created_at: createdISO,
            closed_at: closedISO,
            // amount in HubSpot deals is ex-GST in our integration; use it as fallback
            total_price: props.shopify_total_inc_gst || props.amount || '0',
            total_price_ex_gst: props.shopify_total_ex_gst || props.amount || '0',
            subtotal_price: props.shopify_subtotal || '0',
            total_tax: props.shopify_gst_amount || '0',
            total_shipping_price_set: {
              shop_money: {
                amount: props.shopify_shipping_cost || '0'
              }
            },
            currency: props.hs_deal_currency_code || 'AUD',
            financial_status: 'paid', // All HubSpot deals are closed won
            fulfillment_status: 'fulfilled',
            customer: enrich ? {
              email: contactEmail || `hubspot-deal-${deal.id}@exposurepack.com.au`,
              first_name: contactFirst,
              last_name: contactLast,
              name: contactFullName || undefined,
              company: contactCompany || undefined,
              default_address: contactCompany ? { company: contactCompany } : undefined
            } : { email: `hubspot-deal-${deal.id}@exposurepack.com.au` },
            // Include display fields only when enriched
            ...(enrich ? { display_business_name: contactCompany || undefined, display_customer_name: contactFullName || undefined } : {}),
            line_items: [], // Could be enhanced later with associated line items
            tags: ['hubspot-import'],
            
            // Additional HubSpot metadata
            hubspot_deal_id: deal.id,
            hubspot_deal_stage: props.dealstage,
            deal_source: props.deal_source || 'HubSpot',
            data_source: 'hubspot'
          };
        });
        
        analyticsData = {
          source: 'hubspot',
          orders: transformedOrders,
          total_count: transformedOrders.length,
          hubspot_available: true,
          deals_fetched: hubspotDeals.length
        };
        
        console.log(`✅ HubSpot data: ${hubspotDeals.length} deals transformed to orders`);
        
      } catch (hubspotError) {
        console.error("❌ HubSpot fetch failed, falling back to Shopify data:", hubspotError.message);
        
        // Fall back to Shopify data
        analyticsData.hubspot_error = hubspotError.message;
      }
    }
    
    // If no HubSpot data, fetch from Shopify as fallback
    if (analyticsData.source === 'fallback') {
      try {
        console.log("🛒 Fetching all Shopify orders as fallback...");
        
        // Fetch ALL orders with pagination to ensure we get complete data
        let allShopifyOrders = [];
        let nextPageUrl = `${process.env.SHOPIFY_STORE_URL ? `https://${process.env.SHOPIFY_STORE_URL}` : 'https://exposurepack-myshopify-com.myshopify.com'}/admin/api/${SHOPIFY_API_VERSION}/orders.json?limit=250&status=any`;
        let pageCount = 0;
        const maxPages = 20; // Safety limit to prevent infinite loops
        
        while (nextPageUrl && pageCount < maxPages) {
          pageCount++;
          console.log(`📄 Fetching Shopify page ${pageCount}...`);
          
          const shopifyResponse = await fetch(nextPageUrl, {
            headers: {
              'X-Shopify-Access-Token': SHOPIFY_ACCESS_TOKEN
            }
          });
          
          if (!shopifyResponse.ok) {
            throw new Error(`Shopify API error: ${shopifyResponse.status}`);
          }
          
          const shopifyData = await shopifyResponse.json();
          const pageOrders = shopifyData.orders || [];
          
          allShopifyOrders = allShopifyOrders.concat(pageOrders);
          console.log(`✅ Page ${pageCount}: ${pageOrders.length} orders, Total: ${allShopifyOrders.length}`);
          
          // Check for next page link in headers
          const linkHeader = shopifyResponse.headers.get('Link');
          nextPageUrl = null;
          
          if (linkHeader) {
            const links = linkHeader.split(',');
            for (const link of links) {
              if (link.includes('rel="next"')) {
                const urlMatch = link.match(/<([^>]+)>/);
                if (urlMatch) {
                  nextPageUrl = urlMatch[1];
                  break;
                }
              }
            }
          }
          
          // If no more orders on this page, stop pagination
          if (pageOrders.length === 0) {
            break;
          }
        }
        
        console.log(`📊 Fetched all Shopify orders: ${allShopifyOrders.length} total orders across ${pageCount} pages`);
        
        // Filter by date range if provided
        let orders = allShopifyOrders;
        if (dateRange) {
          const start = new Date(dateRange.startDate);
          const end = new Date(dateRange.endDate);
          orders = orders.filter(order => {
            const orderDate = new Date(order.created_at);
            return orderDate >= start && orderDate <= end;
          });
          console.log(`📅 Filtered to date range: ${orders.length} orders`);
        }
        
        analyticsData = {
          source: 'shopify',
          orders: orders,
          total_count: orders.length,
          hubspot_available: !!hubspotClient,
          shopify_total_available: allShopifyOrders.length,
          pages_fetched: pageCount
        };
        
        console.log(`✅ Shopify fallback complete: ${orders.length} orders for analytics`);
        
      } catch (shopifyError) {
        console.error("❌ Shopify fallback failed:", shopifyError.message);
        
        // Last resort: return empty data with error info
        analyticsData = {
          source: 'error',
          orders: [],
          total_count: 0,
          hubspot_available: !!hubspotClient,
          errors: {
            shopify: shopifyError.message,
            hubspot: analyticsData.hubspot_error
          }
        };
      }
    }
    
    const processingTime = Date.now() - startTime;
    
    res.json({
      ...analyticsData,
      timestamp: new Date().toISOString(),
      processing_time_ms: processingTime
    });
    
    console.log(`⏱️ Analytics request completed in ${processingTime}ms - Source: ${analyticsData.source}`);
    
  } catch (error) {
    const processingTime = Date.now() - startTime;
    console.error("❌ Analytics endpoint error:", error.message);
    
    res.status(500).json({
      source: 'error',
      orders: [],
      total_count: 0,
      hubspot_available: !!hubspotClient,
      error: error.message,
      processing_time_ms: processingTime
    });
  }
});

/**
 * GA4 connectivity status endpoint
 * Checks env configuration and attempts a tiny report via GA4 Data API when library is available
 */
app.get("/ads/ga4-status", async (req, res) => {
  try {
    const propertyId = process.env.GA4_PROPERTY_ID || null;
    const serviceJson = process.env.GA_SERVICE_ACCOUNT_JSON || null;

    const configured = !!propertyId && !!serviceJson;
    let canQuery = false;
    const details = {};

    if (configured) {
      try {
        // Lazy import so the server still runs even if the package isn't installed yet
        const mod = await import('@google-analytics/data').catch(() => null);
        if (!mod || (!mod.BetaAnalyticsDataClient && !mod.v1Beta)) {
          details.error = "@google-analytics/data not installed. Run: npm i @google-analytics/data";
        } else {
          const BetaClient = mod.BetaAnalyticsDataClient || mod.v1Beta.BetaAnalyticsDataClient;
          const creds = JSON.parse(serviceJson);
          const client = new BetaClient({ credentials: creds });
          const [report] = await client.runReport({
            property: `properties/${propertyId}`,
            dateRanges: [{ startDate: 'yesterday', endDate: 'today' }],
            metrics: [{ name: 'screenPageViews' }],
            limit: 1
          });
          canQuery = true;
          details.sampleRows = report?.rows?.length || 0;
        }
      } catch (e) {
        details.error = e.message;
      }
    }

    return res.json({ ok: true, configured, propertyId, canQuery, details });
  } catch (err) {
    return res.status(200).json({ ok: false, error: err.message });
  }
});

// ===== Google OAuth routes and GA4 helper middleware =====
const ensureGoogle = async (req, res, next) => {
  try {
    const ses = req.session || {};
    const g = ses.google || {};
    if (!g.accessToken) {
      return res.status(401).json({ error: "Google not connected. Visit /auth/google first." });
    }
    // Refresh if expiring/expired
    if (!g.expiryDate || Date.now() >= g.expiryDate - 60000) {
      if (!g.refreshToken || !GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
        return res.status(401).json({ error: "Google access token expired and cannot be refreshed" });
      }
      const params = new URLSearchParams({
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        refresh_token: g.refreshToken,
        grant_type: 'refresh_token'
      });
      const resp = await axios.post('https://oauth2.googleapis.com/token', params.toString(), {
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      const data = resp.data || {};
      req.session.google.accessToken = data.access_token;
      req.session.google.expiryDate = Date.now() + ((data.expires_in || 3600) * 1000);
    }
    req.googleAccessToken = req.session.google.accessToken;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Failed to ensure Google token", details: e.message });
  }
};

// Start Google OAuth (request offline access for refresh_token)
app.get('/auth/google',
  (req, res, next) => {
    const scope = [
      "https://www.googleapis.com/auth/userinfo.email",
      "https://www.googleapis.com/auth/analytics.readonly",
      "https://www.googleapis.com/auth/adwords",
      "openid",
      "profile"
    ];
    // Optionally carry a `state` param to redirect back to your dashboard
    passport.authenticate('google', {
      scope,
      accessType: 'offline',
      prompt: 'consent',
      state: req.query.state || ''
    })(req, res, next);
  }
);

// OAuth callback: persist tokens in session, redirect to admin dashboard
app.get('/auth/google/callback', (req, res, next) => {
  passport.authenticate('google', { failureRedirect: '/auth/google/failure' }, (err, user) => {
    if (err || !user) return res.redirect('/auth/google/failure');
    req.login(user, (loginErr) => {
      if (loginErr) return res.redirect('/auth/google/failure');
      // Persist tokens in session for API usage
      req.session.google = {
        accessToken: user.tokens?.accessToken || null,
        refreshToken: user.tokens?.refreshToken || null,
        expiryDate: user.tokens?.expiryDate || null,
        profile: user.profile || null
      };
      const redirectUrl = req.query.state ? decodeURIComponent(req.query.state) : '/';
      return res.redirect(redirectUrl);
    });
  })(req, res, next);
});

app.get('/auth/google/failure', (req, res) => {
  res.status(401).json({ error: "Google authentication failed" });
});

app.post('/auth/google/logout', (req, res) => {
  try {
    if (req.logout) req.logout(() => {});
    if (req.session) req.session.google = null;
    res.json({ ok: true });
  } catch (e) {
    res.json({ ok: true });
  }
});

// GA4 Summary: last 7 days activeUsers + sessions
app.get('/api/ga4/summary', ensureGoogle, async (req, res) => {
  try {
    const propertyId = req.query.propertyId || GA4_PROPERTY_ID || GA4_DEFAULT_PROPERTY_ID;
    if (!propertyId) {
      return res.status(400).json({ error: "GA4 property ID required. Supply ?propertyId=... or set GA4_PROPERTY_ID/GA4_DEFAULT_PROPERTY_ID." });
    }
    const url = `https://analyticsdata.googleapis.com/v1beta/properties/${propertyId}:runReport`;
    const body = {
      dateRanges: [{ startDate: "7daysAgo", endDate: "today" }],
      metrics: [{ name: "activeUsers" }, { name: "sessions" }]
    };
    const { data } = await axios.post(url, body, {
      headers: {
        Authorization: `Bearer ${req.googleAccessToken}`,
        'Content-Type': 'application/json'
      }
    });
    res.json({
      ok: true,
      propertyId,
      summary: data
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: "Failed to fetch GA4 summary",
      details: error.response?.data || error.message
    });
  }
});

// GA4: list accessible properties for the current OAuth user
app.get('/api/ga4/properties', ensureGoogle, async (req, res) => {
  try {
    // Use Admin API Account Summaries to list properties
    // https://analyticsadmin.googleapis.com/v1beta/accountSummaries
    const results = [];
    let nextPageToken = undefined;
    for (let i = 0; i < 5; i++) { // safety cap
      const url = new URL('https://analyticsadmin.googleapis.com/v1beta/accountSummaries');
      if (nextPageToken) url.searchParams.set('pageToken', nextPageToken);
      url.searchParams.set('pageSize', '200');
      const { data } = await axios.get(url.toString(), {
        headers: { Authorization: `Bearer ${req.googleAccessToken}` }
      });
      const summaries = Array.isArray(data?.accountSummaries) ? data.accountSummaries : [];
      for (const acc of summaries) {
        const accountName = acc.displayName || acc.name || '';
        const props = Array.isArray(acc.propertySummaries) ? acc.propertySummaries : [];
        for (const p of props) {
          const propertyResource = p.property || '';
          const id = propertyResource.replace('properties/', '');
          results.push({
            propertyId: id,
            propertyResource,
            propertyDisplayName: p.displayName || id,
            accountDisplayName: accountName,
            account: acc.name || ''
          });
        }
      }
      nextPageToken = data?.nextPageToken;
      if (!nextPageToken) break;
    }
    res.json({ ok: true, count: results.length, properties: results });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.response?.data || error.message });
  }
});

// Google Ads: basic summary (last 7 days) - clicks, impressions, cost
app.get('/api/google-ads/summary', ensureGoogle, async (req, res) => {
  try {
    const developerToken = ADS_DEVELOPER_TOKEN;
    const rawLoginId = req.query.loginCustomerId || ADS_LOGIN_CUSTOMER_ID || '';
    const loginCustomerId = rawLoginId ? String(rawLoginId).trim().replace(/\D/g, '') : undefined;
    const rawCustomerId = (req.query.customerId || ADS_DEFAULT_CUSTOMER_ID || '');
    const customerId = String(rawCustomerId).trim().replace(/\D/g, '');
    if (!developerToken) return res.status(400).json({ ok: false, error: 'ADS_DEVELOPER_TOKEN not configured' });
    if (!customerId) return res.status(400).json({ ok: false, error: 'Google Ads customerId required (customerId=1234567890)' });

    // REST path for SearchStream
    const endpoint = `https://googleads.googleapis.com/v17/customers/${customerId}/googleAds:searchStream`;
    const query = `
      SELECT
        metrics.clicks,
        metrics.impressions,
        metrics.cost_micros
      FROM campaign
      WHERE segments.date BETWEEN '7 DAYS AGO' AND 'TODAY'
    `;
    const headers = {
      Authorization: `Bearer ${req.googleAccessToken}`,
      'developer-token': developerToken,
      'Content-Type': 'application/json',
      ...(loginCustomerId ? { 'login-customer-id': loginCustomerId } : {})
    };
    const { data } = await axios.post(endpoint, { query }, { headers });
    // data is a stream of responses; sum metrics
    let clicks = 0, impressions = 0, costMicros = 0;
    const chunks = Array.isArray(data) ? data : [];
    for (const chunk of chunks) {
      const rows = Array.isArray(chunk.results) ? chunk.results : [];
      for (const row of rows) {
        clicks += Number(row.metrics?.clicks || 0);
        impressions += Number(row.metrics?.impressions || 0);
        costMicros += Number(row.metrics?.costMicros || row.metrics?.cost_micros || 0);
      }
    }
    res.json({ ok: true, customerId, loginCustomerId: loginCustomerId || null, metrics: { clicks, impressions, cost_micros: costMicros, cost: costMicros / 1_000_000 } });
  } catch (error) {
    res.status(500).json({ ok: false, error: error.response?.data || error.message });
  }
});
/**
 * Shopify webhook endpoint for order creation
 * Creates a deal in HubSpot when a new order is placed
 */
app.post("/shopify-webhook", async (req, res) => {
  const startTime = Date.now();
  
  try {
    console.log("🛒 Shopify webhook received - Order created");
    if (LOG_VERBOSE) {
      console.log("🔍 Headers:", {
        'x-shopify-topic': req.headers['x-shopify-topic'],
        'x-shopify-shop-domain': req.headers['x-shopify-shop-domain'],
        'x-shopify-webhook-id': req.headers['x-shopify-webhook-id'],
        'content-type': req.headers['content-type'],
        'user-agent': req.headers['user-agent']
      });
    }
    if (LOG_VERBOSE) console.log("🔍 Raw body type:", typeof req.body);
    
    // Verify this is an order creation webhook
    const webhookTopic = req.headers['x-shopify-topic'];
    if (webhookTopic !== 'orders/create') {
      console.log(`⚠️ Unexpected webhook topic: ${webhookTopic}, expected: orders/create`);
      return res.status(200).json({ received: true, processed: false, message: `Ignoring webhook topic: ${webhookTopic}` });
    }
    
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

    // Validate order data
    if (!order || !order.id || !order.name) {
      console.error("❌ Invalid order data - missing required fields (id, name)");
      console.log("📝 Received order data:", JSON.stringify(order, null, 2));
      return res.status(200).json({ received: true, processed: false, message: "Invalid order data" });
    }

    console.log(`🛒 Processing Shopify order: ${order.name} (ID: ${order.id})`);
    console.log(`💰 Order total: ${order.total_price} ${order.currency || 'AUD'}`);
    console.log(`👤 Customer: ${order.customer?.email || 'N/A'}`);
    console.log(`📦 Line items: ${order.line_items?.length || 0}`);

    // Order-level idempotency: skip if we've just processed this order ID
    if (wasOrderRecentlyProcessed(order.id)) {
      console.log(`🛑 Skipping HubSpot deal creation for order ${order.name}: recently processed`);
      return res.status(200).json({ received: true, processed: false, message: 'Duplicate order webhook skipped' });
    }

    // Guard: Skip creating HubSpot deal for orders that originated from HubSpot
    const tagsValue = Array.isArray(order.tags) ? order.tags.join(',') : (order.tags || '');
    const tagsLower = String(tagsValue).toLowerCase();
    const hasHubspotTag = tagsLower.includes('hubspot');
    const hasHubspotImportTag = tagsLower.includes('hubspot-import');
    const hasHubspotNoteAttr = Array.isArray(order.note_attributes) && order.note_attributes.some(na => {
      const name = String(na?.name ?? '').toLowerCase();
      const rawVal = na?.value;
      const valueStr = rawVal == null ? '' : (typeof rawVal === 'string' ? rawVal : JSON.stringify(rawVal));
      const value = valueStr.toLowerCase();
      return name === 'hubspot_deal_id' || value.includes('hubspot') || value === 'hubspot_webhook';
    });

    if (hasHubspotTag || hasHubspotImportTag || hasHubspotNoteAttr) {
      console.log('🛑 Skipping HubSpot deal creation for order with HubSpot indicators:', {
        tags: tagsValue,
        hasHubspotTag,
        hasHubspotImportTag,
        hasHubspotNoteAttr
      });
      return res.status(200).json({
        received: true,
        processed: false,
        message: 'Skipped HubSpot deal creation for order imported from HubSpot',
        orderId: order.id,
        orderNumber: order.name
      });
    }

    // Extra guard: if a HubSpot deal already exists for this Shopify order, skip creating another
    try {
      const existingDeals = await hubspotClient.searchDealsByShopifyOrder(order.id, order.name);
      if (Array.isArray(existingDeals) && existingDeals.length > 0) {
        console.log(`🛑 Existing HubSpot deal(s) found for order ${order.name}. Skipping creation.`);
        markOrderProcessed(order.id);
        return res.status(200).json({ received: true, processed: false, message: 'Existing deal found, skipped', orderId: order.id });
      }
    } catch (searchErr) {
      console.warn(`⚠️ Failed to search existing HubSpot deals for order ${order.name}:`, searchErr.message);
    }

    // Create HubSpot deal from Shopify order
    const createdDeal = await createHubSpotDealFromShopifyOrder(order);
    // Mark order processed to prevent rapid duplicate processing
    markOrderProcessed(order.id);

    const processingTime = Date.now() - startTime;
    console.log(`⏱️ Webhook processing completed in ${processingTime}ms`);

    res.status(200).json({ 
      received: true, 
      processed: true, 
      message: "Deal created in HubSpot successfully",
      orderId: order.id,
      orderNumber: order.name,
      hubspotDealId: createdDeal?.id || null,
      processingTimeMs: processingTime
    });

  } catch (error) {
    const processingTime = Date.now() - startTime;
    console.error("❌ Error processing Shopify webhook:", error.message);
    console.error("❌ Stack trace:", error.stack);
    console.error(`⏱️ Failed after ${processingTime}ms`);
    
    // Always return 200 to prevent Shopify retries
    res.status(200).json({ 
      received: true, 
      processed: false, 
      error: error.message,
      message: "Error occurred but webhook acknowledged",
      processingTimeMs: processingTime
    });
  }
});

/**
 * Shopify customer webhook (create/update/enable/disable)
 * Syncs customer to HubSpot contact without loops
 */
app.post("/shopify-customer-webhook", async (req, res) => {
  try {
    const topic = req.headers['x-shopify-topic'] || '';
    console.log("🧩 Shopify customer webhook received", { topic });
    const isCustomerEvent = /customers\//i.test(topic);
    if (!isCustomerEvent) {
      return res.status(200).json({ received: true, processed: false, message: 'Ignored non-customer webhook' });
    }

    const customer = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    console.log("🧩 Customer payload", { id: customer?.id, email: customer?.email });
    if (!customer || !customer.id || !customer.email) {
      return res.status(200).json({ received: true, processed: false, message: 'Invalid customer payload' });
    }

    // Idempotency on customer events
    if (wasCustomerRecentlyProcessed(customer.id)) {
      return res.status(200).json({ received: true, processed: false, message: 'Duplicate customer webhook skipped' });
    }

    // Map Shopify customer → HubSpot contact properties
    const phoneCandidates = [
      customer.phone,
      customer?.default_address?.phone,
      ...(Array.isArray(customer?.addresses) ? customer.addresses.map(a => a?.phone).filter(Boolean) : [])
    ].filter(Boolean);
    const phone = phoneCandidates[0] || '';

    const addr = customer.default_address || {};
    const contactData = {
      email: customer.email,
      firstname: customer.first_name || '',
      lastname: customer.last_name || '',
      phone,
      address: addr.address1 || '',
      city: addr.city || '',
      state: addr.province || '',
      country: addr.country || '',
      zip: addr.zip || '',
      company: addr.company || ''
    };
    console.log("🧩 Upserting contact to HubSpot", { email: contactData.email, phone: contactData.phone });

    // Upsert to HubSpot
    try {
      const upserted = await hubspotClient.createOrUpdateContact(contactData);
      console.log("✅ HubSpot contact upserted", { id: upserted?.id || upserted?.hs_object_id, email: contactData.email });
    } catch (err) {
      // If conflict, fallback to search and patch
      try {
        const searchRes = await axios.post(
          `${hubspotClient.baseURL}/crm/v3/objects/contacts/search`,
          { filterGroups: [{ filters: [{ propertyName: 'email', operator: 'EQ', value: contactData.email }] }] },
          { headers: hubspotClient.headers }
        );
        const hit = Array.isArray(searchRes?.data?.results) ? searchRes.data.results[0] : null;
        if (hit && hit.id) {
          const patchRes = await axios.patch(
            `${hubspotClient.baseURL}/crm/v3/objects/contacts/${hit.id}`,
            { properties: contactData },
            { headers: hubspotClient.headers }
          );
          console.log("✅ HubSpot contact patched", { id: hit.id, email: contactData.email });
        }
      } catch (fallbackErr) {
        console.error("❌ HubSpot contact upsert failed", fallbackErr.response?.data || fallbackErr.message);
      }
    }

    // Mark processed
    markCustomerProcessed(customer.id);
    return res.status(200).json({ received: true, processed: true });
  } catch (error) {
    return res.status(200).json({ received: true, processed: false, error: error.message });
  }
});

/**
 * HubSpot webhook endpoint for deal stage changes
 * Bypasses authentication for webhook calls
 */
app.post("/webhook", async (req, res) => {
  try {
    console.log("🎯 HubSpot webhook received");
    if (LOG_VERBOSE) {
      console.log("🔍 Headers:", req.headers);
      console.log("🔍 Raw body type:", typeof req.body);
      console.log("🔍 Raw body:", req.body);
    }

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

    const { objectId, propertyName, newValue, propertyValue, subscriptionType } = dealData;
    
    // HubSpot can send either 'newValue' or 'propertyValue'
    const value = newValue || propertyValue;

    console.log(`🔍 Processing: objectId=${objectId}, propertyName=${propertyName}, value=${value}`);
    console.log(`🔍 Deal data keys:`, Object.keys(dealData));

    // Handle HubSpot contact changes → sync to Shopify (no loops)
    if (subscriptionType && String(subscriptionType).startsWith('contact.')) {
      try {
        const contactId = dealData.objectId;
        if (contactId && !wasHubspotContactRecentlyProcessed(contactId)) {
          // Pull contact details
          const contact = await hubspotClient.getContact(contactId);
          const p = contact?.properties || {};
          const email = p.email || null;
          if (email) {
            // Upsert to Shopify by email
            try {
              const search = await restClient.get(`/customers/search.json?query=${encodeURIComponent(`email:${email}`)}`);
              const existing = Array.isArray(search?.customers) && search.customers[0];
              const payload = {
                customer: {
                  email,
                  first_name: p.firstname || '',
                  last_name: p.lastname || '',
                  phone: p.phone || undefined,
                  default_address: {
                    address1: p.address || p.address1 || '',
                    city: p.city || '',
                    province: p.state || '',
                    country: p.country || '',
                    zip: p.zip || ''
                  }
                }
              };
              if (existing) {
                console.log("🧩 Updating Shopify customer from HubSpot", { shopify_customer_id: existing.id, email });
                await restClient.put(`/customers/${existing.id}.json`, payload);
                console.log("✅ Shopify customer updated", { shopify_customer_id: existing.id });
              } else {
                console.log("🧩 Creating Shopify customer from HubSpot", { email });
                const created = await restClient.post(`/customers.json`, payload);
                console.log("✅ Shopify customer created", { shopify_customer_id: created?.customer?.id });
              }
              // Only mark processed for integration-originated changes to avoid skipping CRM_UI updates
              if ((dealData.changeSource || '').toUpperCase() !== 'CRM_UI') {
                markHubspotContactProcessed(contactId);
              }
            } catch (_) {}
          }
        }
      } catch (_) {}
      return res.status(200).json({ received: true, processed: true });
    }

    // Check if this is a dealstage change to closedwon and originated from the CRM UI (not our app)
    const fromIntegration = (dealData.changeSource && String(dealData.changeSource).toUpperCase() !== 'CRM_UI');
    const sourceId = String(dealData.sourceId || '');
    const isSelfEvent = sourceId.includes(process.env.HUBSPOT_APP_ID || '');
    if (fromIntegration && isSelfEvent) {
      console.log(`🛑 Ignoring closedwon from integration/self to prevent ping-pong (sourceId=${sourceId})`);
      return res.status(200).json({ received: true, processed: false, message: 'Ignored integration-originated event' });
    }

    if (propertyName === 'dealstage' && value === 'closedwon') {
      console.log(`🎉 Deal ${objectId} moved to 'closedwon'`);

      // Idempotency: skip if we've processed this deal recently
      if (wasDealRecentlyProcessed(objectId)) {
        console.log(`🛑 Skipping duplicate processing for deal ${objectId} (recently processed)`);
        return res.status(200).json({ received: true, processed: false, message: 'Duplicate closedwon event skipped', dealId: objectId });
      }

      // Secondary guard: if an order already exists for this deal, skip
      const existing = await findExistingShopifyOrderForDeal(objectId);
      if (existing) {
        console.log(`🛑 Shopify order already exists for deal ${objectId} → Order #${existing?.name || existing?.order_number || existing?.id}`);
        markDealProcessed(objectId);
        return res.status(200).json({ received: true, processed: false, message: 'Order already exists for deal', dealId: objectId, orderId: existing.id, orderNumber: existing.name || existing.order_number });
      }

      console.log(`🚀 Creating Shopify order from HubSpot deal ${objectId}`);

      try {
        // Concurrency lock to prevent simultaneous processing of same deal
        if (!acquireDealLock(objectId)) {
          console.log(`🛑 Another process is already handling deal ${objectId}. Skipping.`);
          return res.status(200).json({ received: true, processed: false, message: 'In-flight duplicate skipped', dealId: objectId });
        }
        const result = await createShopifyOrderFromHubspotInvoice(objectId);
        
        console.log(`✅ Successfully created Shopify order from HubSpot deal ${objectId}`);

        // Mark processed to avoid re-runs in quick succession
        markDealProcessed(objectId);
        
        return res.status(200).json({
          received: true,
          processed: true,
          message: "Shopify order created successfully",
          dealId: objectId,
          shopifyOrder: result.order
        });

      } catch (orderError) {
        console.error(`❌ Failed to create Shopify order from deal ${objectId}:`, orderError.message);

        // Still mark as processed briefly to prevent tight retry loops from HubSpot
        markDealProcessed(objectId);
        
        // Still return 200 to prevent HubSpot retries, but log the error
        return res.status(200).json({
          received: true,
          processed: false,
          message: "Failed to create Shopify order",
          error: orderError.message,
          dealId: objectId
        });
      } finally {
        releaseDealLock(objectId);
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
  console.log("   📮 PUT  /orders/:id/shipping-address - Update order shipping address");
  console.log("✅ ===============================================");
}); 
