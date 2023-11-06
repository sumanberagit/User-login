const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv").config();

const app = express();


// middlewares
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const userRoutes = require('./routes/userRoutes');

app.use('/api/user/', userRoutes);


// starting server
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
  .then(() => {
    console.log(`Connected to MongoDB`);
  })
  .then(() => {
    app.listen(process.env.PORT || 5000, () => {
      console.log('Server running on port 5000');
    });
  })
  .catch(error => {
    console.log(error);
  });