const express = require("express");
const passportRouter = express.Router();
// Require user model
const User = require("../models/user");

// Add bcrypt to encrypt passwords
// delete 'js' for mac
const bcrypt = require("bcryptjs");
// Add passport 
const passport = require("passport");

passportRouter.get("/private", (req, res, next) => {
  if (req.isAuthenticated()) {

    res.render("passport/private");
  } else {
    res.render("Error", { errorMessage: "This is a private page" })
  }
})

passportRouter.get("/signup", (req, res, next) => {
  res.render("passport/signup");
})

passportRouter.get("/login", (req, res, next) => {
  res.render("passport/login");
})

const ensureLogin = require("connect-ensure-login");


passportRouter.get("/private-page", ensureLogin.ensureLoggedIn(), (req, res) => {
  res.render("passport/private", { user: req.user });
});

passportRouter.post(
  '/login',
  passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/passport/login',
    failureFlash: true,
    passReqToCallback: true
  })
);

passportRouter.post("/signup", (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  const salt = bcrypt.genSaltSync();
  const hashPassword = bcrypt.hashSync(password, salt);

  if (username === '' || password === '') {
    res.render('passport/signup', {
      errorMessage: 'You need a username and a password to register'
    });
    return;
  }


  User.findOne({ username })
    .then(user => {
      if (user) {
        res.render('passport/signup', {
          errorMessage: 'There is already a registered user with this username'
        });
        return;
      }
      User.create({ username, password: hashPassword })
        .then(() => {
          res.redirect('/');
        })
        .catch(err => {
          console.error('Error while registering new user', err);
          next();
        });
    })
    .catch(err => {
      console.error('Error while looking for user', err);
    });
})



module.exports = passportRouter;


