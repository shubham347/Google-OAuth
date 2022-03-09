//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const findOrCreate = require('mongoose-findorcreate');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// const bcrypt = require('bcrypt');
// const saltRounds = 10;
// const md5 = require('md5');
// const encrypt = require('mongoose-encryption');

const app = express();
app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Little Secret.",
  cookie: {},
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
// userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ['password']});
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, {email: profile.emails[0].value}, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get("/", function(req, res){
  res.render('home');
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ["email","profile"] }),
);


app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
    res.send('<script> window.opener.location="/secrets"; window.close();</script>');
    // Successful authentication, redirect secrets.
     // res.redirect("/secrets");
    // res.end();
    // res.render('popup', {user: req.user});
  });

app.get("/register", function(req, res){
  res.render('register');
});

app.get("/login", function(req, res){
  res.render('login');
});

app.get("/secrets", function(req, res){
  if(req.isAuthenticated()){
    User.find({"secret": {$ne:null}}, function(err, foundUsers){
      if(err){
        console.log(err);
      }else {
        res.render('secrets', {user: req.user, usersSecrets: foundUsers});
      }
    });
  }else {
    res.redirect("/login");
  }
});

app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render('submit');
  }else {
    res.redirect("/login");
  }
});

app.post("/submit", function(req, res){
   const submittedSecret = req.body.secret;
   console.log(req.user.id);
   User.findById(req.user.id, function(err, foundUser){
     if(err){
       console.log(err);
     }else {
       if(foundUser){
         foundUser.secret = submittedSecret;
         foundUser.save(function(){
           res.redirect("/secrets");
         });
       }
     }
   })
});

app.get("/logout", function(req, res){
  req.session = null;
  req.logout();
  res.redirect("/");
});

app.post("/register", function(req, res){

  User.register({ username: req.body.username }, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register");
    }else {
      passport.authenticate("local")(req, res, function(err){
        console.log(err);
        res.redirect("/secrets");
      });
    }
  });

  // bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
  //   const newUser = new User({
  //     email: req.body.username,
  //     password: hash
  //   });
  //   newUser.save(function(err){
  //     if(!err){
  //       res.render('secrets')
  //     }else {
  //       console.log(err);
  //     }
  //   });
  // });
});

app.post("/login", function(req, res){
  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
    }
  });
  // const username = req.body.username;
  // const password = req.body.password;
  //
  // User.findOne({email: username}, function(err, founduser){
  //   if(err) {
  //     console.log(err);
  //   }else {
  //     if(founduser){
  //       bcrypt.compare(password, founduser.password, function(err, result) {
  //       if(result === true){
  //           res.render('secrets');
  //       }
  //     });
  //     }
  //   }
  // });
});

app.listen(3000, function(){
  console.log("Server started running on port 3000");
});


//clientID: 208536222878-4fj4huas6ocahdko8hecr86lmic3v7fl.apps.googleusercontent.com
//clientSecret: UFfidAfM1-nBhyZ990QExiAK
