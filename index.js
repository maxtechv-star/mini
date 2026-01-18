const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 5000;
const __root = path.resolve(__dirname);

// Parse JSON and urlencoded bodies
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from /public
app.use(express.static(path.join(__root, 'public')));

// Mount pair router under /code
const codeRouter = require('./pair');
app.use('/code', codeRouter);

// Admin page (if you want a friendly route)
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__root, 'public', 'admin.html'));
});

// Root -> main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__root, 'public', 'main.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

module.exports = app;