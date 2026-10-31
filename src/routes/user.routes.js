import { getUser, login, logout, logoutAllDevice, refreshAccessToken, registerUser, verifyEmail } from "../controllers/user.controller.js";
import {Router} from "express"
import { verifyjwt } from "../middleware/auth.middleware.js";

const router = Router();

router.route("/register").post(registerUser);
router.route("/refresh-token").get(refreshAccessToken)
router.route("/login").post(login)
router.route("/verify-email").post(verifyEmail)

//protected Routes
router.route("/getuser").get(verifyjwt,getUser);
router.route("/logout").get(verifyjwt,logout);
router.route("/logout-all-device").get(verifyjwt,logoutAllDevice)

export default router