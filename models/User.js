const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    firstname: {
        type: String
    },
    lastname: {
        type: String
    },
    phone: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true,
        unique: true
    },
    password: {
        type: String,
        required: true
    },
    // stripeCustomerId: {
    //     type: String,
    //     default: ''
    // },
    resetToken: String,
    resetTokenExpiration: Date,
});

module.exports = mongoose.model('User', userSchema); 