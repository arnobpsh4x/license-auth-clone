const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());

// SQLite database
const db = new sqlite3.Database('./licenses.db');
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT,
  license_key TEXT
)`);

// Signup
app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  const license_key = 'LIC-' + Math.random().toString(36).substr(2, 8).toUpperCase();
  const hashed = bcrypt.hashSync(password, 10);
  db.run('INSERT INTO users (username, password, license_key) VALUES (?, ?, ?)',
    [username, hashed, license_key],
    (err) => {
      if (err) return res.status(400).json({ error: 'Username exists' });
      res.json({ message: 'Success', license_key });
    });
});

// Login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (!user || !bcrypt.compareSync(password, user.password))
      return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id }, 'secretkey', { expiresIn: '1d' });
    res.json({ token, license_key: user.license_key });
  });
});

app.listen(5000, () => console.log('Server running on port 5000'));
