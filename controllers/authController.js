const bcrypt = require('bcryptjs');
const db = require('../config/db');

// Handle signup
exports.signup = async (req, res) => {
  const { email, password } = req.body;

  // Check if user already exists
  const sqlCheck = 'SELECT * FROM users WHERE email = ?';
  db.query(sqlCheck, [email], async (error, results) => {
    if (error) {
      console.error('Database error:', error);
      return res.status(500).send('Internal server error');
    }

    if (results.length > 0) {
      return res.send('User already exists. Please log in.');
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the new user
    const sqlInsert = 'INSERT INTO users (email, password) VALUES (?, ?)';
    db.query(sqlInsert, [email, hashedPassword], (err) => {
      if (err) {
        console.error('Error inserting user:', err);
        return res.status(500).send('Internal server error');
      }
      res.redirect('/auth/login'); // Redirect to login page after successful signup
    });
  });
};

// Handle login
exports.login = (req, res) => {
  const { email, password } = req.body;

  const sqlQuery = 'SELECT * FROM users WHERE email = ?';
  db.query(sqlQuery, [email], async (error, results) => {
    if (error) {
      console.error('Database error:', error);
      return res.status(500).send('Internal server error');
    }

    if (results.length === 0) {
      return res.send('User not found. Please sign up.');
    }

    // Compare passwords
    const user = results[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.send('Invalid email or password');
    }

    // Set user session
    req.session.user = user;
    console.log('User logged in:', req.session.user); // Log the user session for debugging
    res.redirect('/'); // Redirect to the dashboard
  });
};

// Handle logout
exports.logout = (req, res) => {
  req.session.destroy(() => {
    res.redirect('/auth/login'); // Redirect to login page after logout
  });
};
