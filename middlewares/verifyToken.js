const jwt = require("jsonwebtoken")

const verifyToken = async (req, res, next) => {
    const authHeader = await req.get('Authorization');
    if (authHeader) return res.status(403).json({ msg: 'Not authorized. No token' })

    if (authHeader && authHeader.startsWith("Bearer ")) {
        const token = await authHeader.split(' ')[1]
        let decodedToken;
        try {
            //Verify JWT Token
            decodedToken = jwt.verify(token, process.env.secretKey);
        } catch (err) {
            err.statusCode = 500;
            throw err;
        }
        if (!decodedToken) {
            const error = new Error('Not authenticated.');
            error.statusCode = 401;
            throw error;
        }

        req.id = decodedToken.id
        next()

    }
}

module.exports = verifyToken 