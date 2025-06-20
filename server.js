import express from 'express';
import axios from 'axios';
import cors from 'cors';
import dotenv from 'dotenv';
dotenv.config();

const app = express();
app.use(cors());

const SHOP_URL = process.env.SHOPIFY_STORE_URL;
const ACCESS_TOKEN = process.env.SHOPIFY_ACCESS_TOKEN;
const API_VERSION = process.env.SHOPIFY_API_VERSION || '2024-04';

// Optional API key protection
app.use((req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== process.env.FRONTEND_SECRET) {
    return res.status(403).send('Forbidden – bad API key');
  }
  next();
});

// Health check
app.get('/health', (req, res) => {
  res.send('OK ✅');
});

// Orders endpoint
app.get('/orders', async (req, res) => {
  try {
    const response = await axios.get(`https://${SHOP_URL}/admin/api/${API_VERSION}/orders.json`, {
      headers: {
        'X-Shopify-Access-Token': ACCESS_TOKEN
      }
    });
    res.json({
      orders: response.data.orders,
      current_page: 1,
      total_pages: 1,
      total_count: response.data.orders.length
    });
  } catch (error) {
    console.error('Shopify API error:', error.message);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`✅ Proxy server running on port ${PORT}`);
});
