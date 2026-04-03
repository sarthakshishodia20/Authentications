import express from "express";
import * as authController from "../controllers/auth.controller.js";
const authRouter = express.Router();

authRouter.post("/register", authController.register);
authRouter.post("/login", authController.login);
authRouter.get("/getMe", authController.getMe);
authRouter.get("/getRefreshToken", authController.getRefreshToken);
authRouter.get("/logout", authController.logout);
authRouter.get("/logout/all",authController.logoutAll);
export default authRouter;