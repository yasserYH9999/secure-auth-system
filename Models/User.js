import { DataTypes, Model } from "sequelize";
import sequelize from "./index.js";

export class User extends Model {}
User.init(
  {
    name: DataTypes.STRING,
    email: DataTypes.STRING,
    provider: DataTypes.STRING,
    provider_id: DataTypes.STRING,
    verifed: DataTypes.BOOLEAN,
  },
  {
    sequelize,
    modelName: "user",
    tableName: "users",
  }
);
export default User;
