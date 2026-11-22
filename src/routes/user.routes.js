import { forgotPassword, getUser, login, logout, logoutAllDevice, refreshAccessToken, registerUser, resendOTP, resetPassword, verifyEmail } from "../controllers/user.controller.js";
import {Router} from "express"
import { verifyjwt } from "../middleware/auth.middleware.js";

const router = Router();

router.route("/register").post(registerUser);
router.route("/refresh-token").get(refreshAccessToken)
router.route("/login").post(login)
router.route("/verify-email").post(verifyEmail)
router.route("/resend-otp").post(resendOTP)
router.route("/forgot-password").post(forgotPassword)
router.route("/reset-password").post(resetPassword)

//protected Routes
router.route("/getuser").get(verifyjwt,getUser);
router.route("/logout").get(verifyjwt,logout);
router.route("/logout-all-device").get(verifyjwt,logoutAllDevice)

export default router