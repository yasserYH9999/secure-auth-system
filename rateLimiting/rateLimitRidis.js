// const { RateLimiterRedis } = require("rate-limiter-flexible");
// const redis = require("ioredis");

// const redisClient = new redis({
//   // host:"host.docker.internal",
//   port:6379,
// });

// const maxWrontAttemts = 100;

// const limiter = new RateLimiterRedis({
//   storeClient: redisClient,
//   keyPrefix: "login_fail_ip",
//   points: maxWrontAttemts,
//   duration:  60,                 //         <<<<<<<<                   ##########################################
// });

// module.exports = async function loginRateLimiter(req, res, next) {
//   const { ip } = req;
//   try {
//     console.log(ip);
//     await limiter.consume(ip);
//     next();
//   } catch (rejRes) {
//     console.log(rejRes);
//     res.status(429).json({
//       message: "Too many login attempts. Try again later.",
//     });
//   }
// };
