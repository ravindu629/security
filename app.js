//require our dotenv package and we configured it to be able to access our environmental variables
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require('mongoose-encryption');
//const md5 = require("md5");
// const bcrypt = require("bcrypt");
//
// const saltRounds = 10;

const session = require('express-session')
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");


const app = express();

//use public folder as static resource
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

//place this code just above the mongoose.connect() and below the all of other app.uses
//set up our app to use sessions and passport for managing those sessions

//tell our app to use session package and then we set it up with some initial configurations
//set up our session
//initialize session with options
app.use(session({
  secret: 'Our little secret.',
  resave: false,
  saveUninitialized: false
}));

//tell our app to use passport and to initialize the passport package
//in order to use passport first we have to initialize it
//initialize() is a method that comes bundled with passport and sets up passport for us to start using it for authentication
app.use(passport.initialize());

//tell our app to use passport to also set up our session
//use passport to manage our sessions
//use passport for dealing with the sessions
app.use(passport.session());

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

//we tap into our user schema and we are going to add passportLocalMongoose as plugin to it
// passportLocalMongoose is what we are going to use to salt and hash our passwords
//and to save our users into our mongoDB database
userSchema.plugin(passportLocalMongoose);


const User = new mongoose.model("User", userSchema);

//passport local configurations

//use passport local mongoose to create a local log in strategy
passport.use(User.createStrategy());

//set a passport to serialize and deserialize our user
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


app.get("/", function(req, res) {
  res.render("home");
});

app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/secrets", function(req, res) {
  //inside this callback we are going to check to see if the user is authenticated
  // and this is where we relying on passport and session and passport local and passport local mongoose to
  //make sure that if a user is already logged in then we should simply render the secrets page
  if(req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});

app.get("/logout", function(req, res) {
  //here is where we are going to deauthenticate our user and end that user session
  req.logout();

  res.redirect("/");
});




//we use passportLocalMongoose package to setup resgister and login post routes

app.post("/register", function(req, res) {

//this register method come from passport local mongooser package
//callback gives us error or give us the new registered user if everything was fine
User.register({username: req.body.username}, req.body.password, function(err, user) {
  if(err) {
    console.log(err);
    res.redirect("/register");
  } else {
    //if there were no errors we can authenticate our user using passport
    //type of autentication that we performing is local
    passport.authenticate("local")(req, res, function() {
      //this callback only triggered if the authentication was successful and we managed to successfully
      // set up a cookie that saved their current logged in session so will you have to check to see if there are logged in or not

      //this case we are authenticating our user and setting up a logged in session for them
      //then even if they go directly to the secret page, they should automatically be able to view it if they are in fact logged in
      // that is why we need to create our secrets route
      res.redirect("/secrets");
    });
  }
});


  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //
  //   newUser.save(function(err) {
  //     if(err) {
  //       console.log(err);
  //     } else {
  //       res.render("secrets");
  //     }
  //   });
  // });


  });

  app.post("/login", function(req, res) {


    //create new user
    const user = new User({
      username: req.body.username,
      passport: req.body.password
    });

    //use passport to login this user and authenticate them
    //we use login() function that passport gives us and it has to be called on the request object
    req.login(user, function(err) {
      //callback can return error if unable to find that user with that username in our database
      if(err) {
        console.log(err);
      } else {
        //if no errors we are going to authenticate our user
        //authenticate our user using their password and username
        passport.authenticate("local")(req, res, function() {
          //if we successfully authenticate them we are going to redirect them to the secrets route
          res.redirect("/secrets");
        });

      }
    })







    // const username = req.body.username;
    // const password = req.body.password;
    //
    // User.findOne({email: username}, function(err, foundUser) {
    //   if(err) {
    //     console.log(err);
    //   } else {
    //     //initial password that user registered must to be equal to the login password that user type
    //     //compare the hash that is inside our database with the hashed version of their password
    //     // if(foundUser.password === password) {
    //     //   res.render("secrets");
    //     // }
    //
    //     //check our login password is correct
    //     bcrypt.compare(password, foundUser.password, function(err, result) {
    //       //check password after hashing with the salt is equal to the hash that we have got stored in our database
    //       if(result === true) {
    //         res.render("secrets");
    //       } else {
    //         res.redirect("/login");
    //       }
    //     });
    //   }
    // });
  });



app.listen(3000, function(){
  console.log("Server started on port 3000.");
});
