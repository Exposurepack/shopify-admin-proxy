const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());

// 🔐 API key check middleware
app.use((req, res, next) => {
  if (req.headers['x-api-key'] !== process.env.FRONTEND_SECRET) {
    return res.status(403).send('Forbidden');
  }
  next();
});

// ✅ Health check route
app.get('/health', (req, res) => {
  res.send('ok');
});

// 🔄 Orders endpoint (placeholder)
app.get('/orders', async (req, res) => {
  res.json({
    orders: [],
    current_page: 1,
    total_pages: 1,
    total_count: 0
  });
});

// 🚀 Start the server on the correct Render port
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ Proxy server running on port ${PORT}`);
});
