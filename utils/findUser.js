import db from "../server.js";
import AppError from "./AppError.js";

export const findOrCreatUserFromGGL = async (profile) => {
  const provider = "google";
  const provider_id = profile.id;
  const name = profile.displayName;
  const email = profile?.emails?.[0]?.value;

  try {
    const [user] = await db.query(
      "SELECT * FROM users WHERE provider=? AND provider_id=?",
      [provider, provider_id]
    );

    if (user.length !== 0) {
      return user[0];
    }

    const [userEmail] = await db.query("SELECT id FROM users WHERE email=?", [
      email,
    ]);

    if (userEmail.length !== 0) {
      await db.query(
        "UPDATE users SET provider='google', provider_id=? WHERE id=?",
        [provider_id, userEmail[0].id]
      );

      const [updatedUser] = await db.query(
        "SELECT * FROM users WHERE provider=? AND provider_id=?",
        [provider, provider_id]
      );
      return updatedUser[0];
    }

    const [result] = await db.query(
      "INSERT INTO users (name, email, provider, provider_id, verifed) VALUES (?, ?, ?, ?, ?)",
      [name, email, provider, provider_id, 1]
    );

    const [newUser] = await db.query("SELECT * FROM users WHERE id=?", [
      result.insertId,
    ]);

    return newUser[0];
  } catch (err) {
    throw new AppError(err.message || "Error creating user from Google", 500);
  }
};

export default findOrCreatUserFromGGL;
