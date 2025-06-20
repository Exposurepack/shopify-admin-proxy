// order-admin-api.js
const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Proxy is up and running!');
});

app.get('/orders', (req, res) => {
  // Dummy response for now
  res.json([
    { id: 1, order_number: '#1001', status: 'paid' },
    { id: 2, order_number: '#1002', status: 'fulfilled' }
  ]);
});

app.listen(PORT, () => {
  console.log(`Proxy server running on port ${PORT}`);
});
