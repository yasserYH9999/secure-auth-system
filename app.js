import express from "express";
const app = express();
import passport from "passport";
import helmet from "helmet";
import compression from "compression";
import xss from "xss-clean";
import mongoSanitize from "express-mongo-sanitize";
import hpp from "hpp";
import session from "express-session";
import MySQLStoreFactory from "express-mysql-session";
import appError from "./utils/AppError.js";
import globalErrorHandler from "./Controller/errorController.js";
import cors from "cors";
import cookieParser from "cookie-parser";
import routes from "./Routes/routes.js";
import path from "path";
import oauth2 from "./Routes/oauth.js";
import sequelize from "./Models/index.js";
import {AdminJs ,router} from "./admin/admin.js";
import dotenv from "dotenv";
import db from "./server.js"; // Make sure server.js uses export default

dotenv.config();

const MySQLStore = MySQLStoreFactory(session); // Just in ES Module

// connect to db
await sequelize.sync();

app.set("view engine", "ejs");
app.set("views", path.join("./", "views"));

// Initialize Express app
app.use(express.json({ limit: "10kb" }));
app.use(cors());
app.use(cookieParser()); // since we use cookies
app.use(compression());
app.use(xss());
app.use(hpp());
app.use(mongoSanitize());
app.use(
  helmet.contentSecurityPolicy({

    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], 
      imgSrc: [
        "'self'",
        "https://www.gstatic.com",
        "https://upload.wikimedia.org",
      ],
    },
  })
);

//Sessions
const sessionStore = new MySQLStore(
  {
    tableName: "sessions",
    clearExpired: true,
    checkExpirationInterval: 15 * 60 * 1000,
    expiration: 24 * 60 * 60 * 1000,
    resave: false,
    saveUninitialized: false,
  },
  db
);
app.use(
  session({
    secret: process.env.SESSION_SECRET, // Secure session secret
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 1000 * 60 * 60 * 24, httpOnly: true, secure: false }, // The secure option set to true only in production envirement
  })
);
app.use(passport.initialize());
app.use(passport.session());

//Handel the routes
app.use("/", (req, res, next) => {
  console.log(`server requested`);
  next();
});
app.use("/admin", router);
app.use("/", routes);
app.use("/", oauth2);
app.all("*", (req, res, next) => {
  next(new appError(`Can't find ${req.originalUrl}.`, 404));
});

//Error Handler Middleware
app.use(globalErrorHandler);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

// Handle asychrounous rejection
process.on("unhandledRejection", (err) => {
  console.log("Server crached 💥 shuting down ....");
  console.log(err.name, err.message);
  process.exit(1);
});

// module.exports = app;
export default app;