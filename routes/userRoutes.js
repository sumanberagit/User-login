const express = require('express');
const { register, login, createSubscription, sendResetPasswordEmail, resetPassword } = require("../controllers/userController");
const verifyToken = require("../middlewares/verifyToken");
const router = express.Router();

//Public routes
router.post('/register', register);
router.post('/login', login);
router.post('/send-reset-password-email', sendResetPasswordEmail);
router.post('/reset-password/:token', resetPassword);

module.exports = router;
