const jwt = require('jsonwebtoken');
const User = require('../models/User');

const auth = async (req, res, next) => {
    // Get the token from the cookie
    const token = req.cookies.token;

    // Check if the token exists
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET); 
        
        // Optional: Check if the token is blacklisted on the server
        const user = await User.findById(decoded.user.id);
        if (user && user.tokenBlacklist.includes(token)) {
            return res.status(401).json({ msg: 'Token has been logged out' });
        }

        req.user = decoded.user;
        req.token = token; // Store the token for the blacklist check in the logout route
        next();

    } catch (err) {
        // If the token is not valid (e.g., expired or malformed)
        res.status(401).json({ msg: 'Token is not valid' });
    }
};



module.exports = auth;