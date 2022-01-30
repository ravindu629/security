//require our dotenv package and we configured it to be able to access our environmental variables
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require('mongoose-encryption');
//const md5 = require("md5");
const bcrypt = require("bcrypt");

const saltRounds = 10;


const app = express();

//use public folder as static resource
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

//Level 2 --> encryption
//use the secret for encrypt our database
//get the secret from .env file
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

//Level 3 --> hashing
//console.log("weak password hash: " + md5("123456"));
//console.log("strong password hash: " + md5("asdrdsffsgs678DFGSTGF343434@__gdgsh"));


const User = new mongoose.model("User", userSchema);


app.get("/", function(req, res) {
  res.render("home");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.post("/register", function(req, res) {

  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    const newUser = new User({
      email: req.body.username,
      password: hash
    });

    newUser.save(function(err) {
      if(err) {
        console.log(err);
      } else {
        res.render("secrets");
      }
    });
  });


  });

  app.post("/login", function(req, res) {
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({email: username}, function(err, foundUser) {
      if(err) {
        console.log(err);
      } else {
        //initial password that user registered must to be equal to the login password that user type
        //compare the hash that is inside our database with the hashed version of their password
        // if(foundUser.password === password) {
        //   res.render("secrets");
        // }

        //check our login password is correct
        bcrypt.compare(password, foundUser.password, function(err, result) {
          //check password after hashing with the salt is equal to the hash that we have got stored in our database
          if(result === true) {
            res.render("secrets");
          } else {
            res.redirect("/login");
          }
        });
      }
    });
  });



app.listen(3000, function(){
  console.log("Server started on port 3000.");
});
