const mongoose = require("mongoose");
const bcrypt = require('bcrypt');
const jwt = require("jsonwebtoken");
const crypto = require('crypto');
const util = require('util');
const nodemailer = require('nodemailer');
const randomBytesAsync = util.promisify(crypto.randomBytes);
const stripe = require('stripe')("sk_test_51Nzb4KSECkIUp6Tq4u7iAdUcez14CAzbryB1TkvNT1p6HgOnuGYlzNDsfLaNMRMVwkay4LTyaVSL8XzayHyZe9e900ppmUMbg7");



const User = require('../models/User');

const isEmailValid = (email) => {
  // Implement your email validation logic here
  // For example, you can use a regular expression to validate the email format
  // Return true if the email is valid, false otherwise
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

const register = async (req, res) => {
  try {
    const { firstname, lastname, phone, email, password } = req.body;

    const isExistingEmail = await User.findOne({ email });

    //check if email already exists
    if (isExistingEmail) {
      throw new Error("Email is already taken by another user");
    }

    // Validate email format
    if (!isEmailValid(email)) {
      throw new Error("Invalid email address");
    }

    //Hashing password
    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    //Create new user
    const newUser = await User.create({
      firstname: firstname,
      lastname: lastname,
      phone: phone,
      email: email,
      password: hashedPassword
    });

    const { password: _, ...others } = newUser._doc;
    return res.status(201).json({ user: others });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

//Login
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate email format
    if (!isEmailValid(email)) {
      throw new Error("Invalid email address");
    }

    const user = await User.findOne({ email });

    if (!user) {
      throw new Error('Invalid credentials. Try again!');
    }

    //Compare password and hashed password
    const comparePass = await bcrypt.compare(password, user.password);

    if (!comparePass) {
      throw new Error('Invalid credentials. Try again!');
    }

    const { password: _, ...others } = user._doc;

    //Generate jwt token on login
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '8d' });

    //Sending token in response
    return res.status(200).json({ user: others, token });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};

const sendResetPasswordEmail = async (req, res, next) => {
  try {
    const buffer = await randomBytesAsync(32);
    const token = buffer.toString('hex');

    const { email } = req.body;
    if (email) {
      const user = await User.findOne({ email: email });

      // Validate email format
      if (!isEmailValid(email)) {
        throw new Error("Invalid email address");
      }

      if (user) {
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000;
        await user.save();

        //Creating transporter
        var transporter = nodemailer.createTransport({
          host: process.env.EMAIL_HOST,
          port: process.env.EMAIL_PORT,
          auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
          }
        });
        transporter.sendMail({
          to: req.body.email,
          from: process.env.EMAIL_FROM,
          subject: 'Password reset',
          html: `<p>You requested a password reset</p>
            <p>Click this <a href="http://localhost:5000/api/user/reset-password/${token}">link</a> to set a new password.</p>`
        });
        res.send({
          "status": "successful",
          "message": `Reset password link sent to email`,
          "token": token
        });


        
      } else {
        res.send({
          "status": "failed",
          "message": "User not registered"
        });
      }
    } else {
      res.send({
        "status": "failed",
        "message": "Email cannot be blank"
      });
    }

  } catch (error) {
    console.log(error);
  }

}

const resetPassword = async (req, res, next) => {
  try {
    const { newPassword, cnfNewPassword } = req.body;
    const { token } = req.params;
    if (newPassword && cnfNewPassword) {
      if (newPassword === cnfNewPassword) {
        const user = await User.findOne({
          resetToken: token,
          resetTokenExpiration: { $gt: Date.now() }
        });
        const salt = await bcrypt.genSalt(12);
        const newHashPassword = await bcrypt.hash(newPassword, salt);

        user.password = newHashPassword;
        console.log(newHashPassword);
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();
        res.send({
          "status": "success",
          "message": "Password changes successfully"
        });
      } else {
        res.send({
          "status": "failed",
          "message": "New Password and confirm new password do not match"
        });
      }
    } else {
      res.send({
        "status": "failed",
        "message": "New Password cannot be blank"
      });
    }
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
}

module.exports = { register, login, sendResetPasswordEmail, resetPassword };
