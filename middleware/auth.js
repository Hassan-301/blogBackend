const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;
const auth = (req, res, next) => {
    const token = req.header('Authorization');
    if (!token) return res.status(401).send('Access denied.');

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send('Invalid token.');
    }
};

module.exports = auth; 