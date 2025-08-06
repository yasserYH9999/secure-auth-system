import appError from "../utils/AppError.js";
import catchAsync from "./../utils/catchAsync.js";
import db from "../server.js";


// Optional helper to filter allowed fields
const filtered = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el) && obj[el] !== "") newObj[el] = obj[el];
  });
  return newObj;
};

export const Auth = catchAsync(async (req, res, next) => {
  const rawSessionId = req.cookies["connect.sid"];
  if (!rawSessionId) return next(new appError("You Are Not Logged In", 403));

  const sessionID = rawSessionId
    .split(".")[0]
    .replace(/^s%3A/, "")
    .replace(/^s:/, "");

  let session;
  try {
    session = await new Promise((resolve, reject) => {
      req.sessionStore.get(sessionID, (err, sessionData) => {
        if (err) return reject(err);
        resolve(sessionData);
      });
    });
  } catch (err) {
    return next(new appError("Error Reading Session Store", 500));
  }

  if (!session || !session.user)
    return next(new appError("Session Not Found or Invalid", 403));

  const { id } = session.user;
  const [rows] = await db.query("SELECT id FROM users WHERE id = ?", [id]);
  if (!rows.length)
    return next(new appError("Please login and try again", 404));

  req.user = session.user;
  next();
});

export const updateProfile = catchAsync(async (req, res, next) => {
  const body = req.body;
  const userID = req.user.id;

  if (!userID) return next(new appError("Unauthorized", 401));
  if (body.password || body.passwordConfirm)
    return next(new appError("Could Not Update The Password Here", 403));

  const update = filtered(body, "name", "email");
  const keys = Object.keys(update);
  const values = Object.values(update);
  const updateFields = keys.map((field) => `${field} = ?`).join(", ");
  const sql = `UPDATE users SET ${updateFields} WHERE id = ?`;
  await db.query(sql, [...values, userID]);

  res.status(200).json({ message: "Profile updated successfully" });
  delete req.user;
});

export const deleteProfile = catchAsync(async (req, res, next) => {
  const userID = req.user.id;
  if (!userID) return next(new appError("Unauthorized", 401));
  const sql = "UPDATE users SET actif = 0 WHERE id = ?";
  await db.query(sql, [userID]);
  res.status(204).json({ message: "User Deleted" });
});

export default {
  Auth,
  updateProfile,
  deleteProfile
};
