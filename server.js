import { createPool } from "mysql2/promise";
import dotenv from "dotenv";
dotenv.config();


const db = createPool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});
try {
  console.log("Database Connected to the Application");
  // module.exports = db;
} catch (err) {
  console.error("❌ Database Connection Error:", err);
  process.exit(1);
}
// module.exports = db;
export default db;
