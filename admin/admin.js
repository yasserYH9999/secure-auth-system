import AdminJS, { actions } from "adminjs";
import adminJSExpress from "@adminjs/express";
import AdminJSSequelize from "@adminjs/sequelize";
import { User } from "../Models/User.js";
import dotenv from "dotenv";
dotenv.config({ path: "../.env" });

AdminJS.registerAdapter({
  Database: AdminJSSequelize.Database,
  Resource: AdminJSSequelize.Resource,
});

export const AdminJs = new AdminJS({
  resources: [
    {
      resource: User,
      options: {
        actions: {
          print: {
            isAccessible: false,
          },
        },
      },
    },
  ],
  rootPath: "/admin",
});


const default_admin = {
  email: process.env.ADMIN_EMAIL,
  password: process.env.ADMIN_PASSWORD,
};
const authenticate = async (email, password) => {
  if (email === default_admin.email && password === default_admin.password)
    return Promise.resolve(default_admin);
};

// export const router = adminJSExpress.buildRouter(AdminJs);
export const router = adminJSExpress.buildAuthenticatedRouter(AdminJs, {
  authenticate,
  cookieName: "adminjs",
  cookiePassword: process.env.SESSION_SECRET,
});
// export { router, AdminJs };
export default { AdminJs, router };
// export default AdminJS;
