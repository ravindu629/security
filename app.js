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
//use passport-google-oauth20 package as a passport Strategy
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');


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
  username: String,
  password: String,
  googleId: String,
  secret:String
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

//add findOrCreate package as a plugin to our schema
userSchema.plugin(findOrCreate);


const User = new mongoose.model("User", userSchema);

//passport local configurations

//use passport local mongoose to create a local log in strategy
passport.use(User.createStrategy());

// //set a passport to serialize and deserialize our user for local strategy
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());

//use passport package to serialize and deserialize users for all different strategy noy just for local strategy
// used to serialize the user for the session
passport.serializeUser(function(user, done) {
    done(null, user.id);
});

// used to deserialize the user
passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});


//set up our google strategy
//use passport to authenticate our users using Google OAuth
passport.use(new GoogleStrategy({

  //here are all the options for using the google strategy to log in our user
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    //change the callback URL to the same one we put in on the google API dashboard
    callbackURL: "http://localhost:3000/auth/google/secrets",
    //we are no longer gonna be retrieving their profile information from their google plus account but instead we are going to retrieve it from their user info which is simply another endpoint on google
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  // google sends back access token which is the thing that allows us to get data related to that user for a longer period of time,
  // we have got their profile that contains their email, their google id and anything else that we have access to
  function(accessToken, refreshToken, profile, cb) {
    //checkout what we get back from google
    //console log the google profile that we got sent after the user has been authenticated by google
    console.log(profile);
    //finally we use the data that we get back namely their google id to either find a user with that id in our database of users or craete them if they don't exist
    User.findOrCreate({ googleId: profile.id, username: profile.id  }, function (err, user) {
      return cb(err, user);
    });
  }
));





app.get("/", function(req, res) {
  res.render("home");
});

//initiate authentication with google strategy
//use passport to authenticate our user using the google strategy which we set up above as a new google strategy passing in all those things to help google recognize our app which we have set up in the google dashboard
//when we hit up google we are going to tell them what we want is the user's profile and this includes their email and user ID on google which we will be able to use and identify them in the future
app.get("/auth/google",
//initiate authentication on google servers asking them for the user's profile once they have logged in
  passport.authenticate('google', { scope: ["profile"] }));


//this is where google will send the user after it is authenticated them on their server
//we need to add this route to be able to authenticate them locally on our website and to save their logging session and cookies
//this GET request gets made by google when they try to redirect the user back to our website
app.get("/auth/google/secrets",
  //then we are going to authenticate the user locally and if there were any problems we are going to send them back to login page again
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to the secrets page.
    res.redirect("/secrets");
  });


app.get("/register", function(req, res) {
  res.render("register");
});

app.get("/login", function(req, res) {
  res.render("login");
});

app.get("/secrets", function(req, res) {
  //we look through our collection of users and find all the places where the field secret actually has a value
  //look through all of our users in our users collection , look through the secret fields and pick out the users where the secret field is not equal to null
  User.find({"secret": {$ne: null}}, function(err, foundUsers) {
    if(err) {
      console.log(err);
    } else {
      if(foundUsers) {
        res.render("secrets", {usersWithSecrets: foundUsers});
      }
    }
  });
});

app.get("/submit", function(req, res) {
  //inside this callback we are going to check to see if the user is authenticated
  // and this is where we relying on passport and session and passport local and passport local mongoose to
  //make sure that if a user is already logged in then we should simply render the submit page
  if(req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;

  //passport saves the user details because when we initiate a new login session it will save that users details into the request variable
  //console log what saved for my current session
  console.log(req.user);
  console.log(req.user.id);

  //when the user makes that post request i'm going to find the user using req.user.id. because that refers to the id that we have for them in our database


  //add the secret that they submitted to that secret field
  User.findById(req.user.id, function(err, foundUser) {
    if(err) {
      console.log(err);
    } else {
      if(foundUser) {
        foundUser.secret = submittedSecret;
        //save this found user with their newly updated secret
        foundUser.save(function() {
          res.redirect("/secrets");
        });
      }
    }
  });

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
