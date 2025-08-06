import dotenv from "dotenv";
import { Sequelize } from "sequelize";
dotenv.config({ path: "../.env" });

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    dialect: "mysql",
    logging: false,
  }
);

try {
  await sequelize.authenticate();
  console.log("Admin panel connected to DB");
} catch (err) {
  console.log(err.message);
}
export default sequelize;
