import express from "express";
import db from "../server.js";
import passport from "passport";
import GoogleStrategy from "passport-google-oidc";
import { findOrCreatUserFromGGL } from "../utils/findUser.js";
import appError from "../utils/AppError.js";
import dotenv from "dotenv";
dotenv.config({ path: "../.env" });

const Router = express.Router();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "/oauth2/redirect/google",
      scope: ["openid", "profile", "email"],
    },
    async function (issuer, profile, done) {
      const user = await findOrCreatUserFromGGL(profile);
      return done(null, user);
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  const user = await db.query("SELECT * FROM users WHERE id=?", id);
  done(null, user[0]);
});

//render the login page
Router.route("/api/login").get((req, res, next) => {
    res.render("login");
});

//IF the User Successfully logedin, The user page rendered
Router.route("/").get((req, res, next) => {
  if (!req.user) return res.render("login");
  return res.render("index", { user: req.user[0] });
});

//Redirect to google
Router.route("/login/auth/google").get(passport.authenticate("google"));

//Handel Callback
Router.route("/oauth2/redirect/google").get(
  passport.authenticate("google", {
    failureRedirect: "/api/login",
    successRedirect: "/",
  })
);

//Logout
Router.route("/logout").post((req, res, next) => {
  res.logout((err) => {
    if (err) next(new appError(err, 500));
    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.redirect("/");
    });
  });
});


export default Router;

