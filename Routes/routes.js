import express from "express";
import { body } from "express-validator";
import userController from "./../Controller/Authentication.js";
import mfa from "../Controller/MFA/mfa.js";
// import loginRateLimiter from "../rateLimiting/rateLimitRidis.js";
import { loginLimiter } from "../rateLimiting/rateLimitMidd.js";
import userControlle from "../Controller/userController.js";

const Router = express.Router();

//Register Route
Router.route("/register").post(
  [
    body("name").trim().notEmpty().withMessage("Name is required"),
    body("email").isEmail().withMessage("Invalid email format"),
    body("password")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long"),
  ],
  userController.register
);

//Login Route
Router.route("/api/login").post(
  [
    body("email").isEmail().withMessage("Invalid email format"),
    body("password").notEmpty().withMessage("Password is required"),
  ],
  loginLimiter,
  userController.login
);

//Admin Route - Based-Role Access Control (BRAC)
Router.route("/api/admin").get(
  userController.authenticationMiddleWare,
  userController.roleMiddleWare("admin"),
  (req, res) => {
    return res.status(200).json({ message: "Welcom Admin" });
  }
);

//Forgot password Route
Router.route("/api/forgot-password").post(userController.forgotPassword);
Router.route("/api/reset-password/").post(
  [
    body("newPassword")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long"),
    body("passwordConfirm")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long"),
  ],
  userController.resetPassword
);

//Email verification Route
Router.route("/api/sent-verification/").post(
  userController.sendVerificationToEmail
);
Router.route("/api/email-verification/").get(userController.verifyEmail);

//Enable--Disable MFA
Router.route("/api/enable-mfa").post(
  userController.authenticationMiddleWare,
  mfa.enableMfa
);
Router.route("/api/disable-mfa").post(
  userController.authenticationMiddleWare,
  mfa.disableMfa
);

//Verify OTP
Router.route("/api/verify-otp").post(
  [body("otp").isEmpty().withMessage("Otp is required")],
  mfa.verifyOtp
);

//Logout Route
// Router.route("/api/logout").get(userController.logout);
Router.route("/logout").get((req, res, next) => {
  req.logout((err) => {
    if (err) next(new appError(err, 500));
    req.session.destroy(() => {
      res.clearCookie("connect.sid");
      res.redirect("/");
    });
  });
});

//Proteced
Router.route("/protected").get(userControlle.Auth, (req, res) => {
  res.send("hello");
});

//Update password
Router.route("/api/update-password").post(
  [
    body("newPassword")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long"),
    body("passwordConfirm")
      .isLength({ min: 6 })
      .withMessage("Password must be at least 6 characters long"),
  ],
  userControlle.Auth,
  userController.updatePassword
);

//Update user
Router.route("/api/update-profile").patch(
  userControlle.Auth,
  userControlle.updateProfile
);

//Delete user
Router.route("/api/delete-profile").delete(
  userControlle.Auth,
  userControlle.deleteProfile
);

// module.exports = Router;
export default Router;
