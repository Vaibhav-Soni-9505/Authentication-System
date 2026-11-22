import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import config from "../config/config.js";
import mongoose from "mongoose";
import bcrypt from "bcrypt"
import { Session } from "../models/session.model.js";
import { sendEmail } from "../services/email.service.js";
import { generateOTP, emailVerificationOtpTemplate } from "../utils/emailVerificaionOtpTemplate.js";
import { passwordResetOtpTemplate } from "../utils/passwordResetOtpTempelate.js";
import { OTP } from "../models/otp.model.js";
import { OTP_COOLDOWN,OTP_WINDOW,MAX_OTP_SENDS,OTP_EXPIRY } from "../config/otp.constants.js";


const generateAccessandRefreshToken = async(user,req)=>{
  try {
    const sessionID = new mongoose.Types.ObjectId();
    const refreshToken = user.generateRefreshToken(sessionID);
    const refreshTokenHash = await bcrypt.hash(refreshToken,10);
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    
    const session = await Session.create({
      _id: sessionID,
      userId: user._id,
      refreshTokenHash,
      ip: req.ip,
      userAgent:req.headers["user-agent"],
      expiresAt
    })

    const accessToken = user.generateAccessToken(sessionID);

    return {accessToken,refreshToken};  
  } catch (error) {
    throw new ApiError(500,"Something went wrong while generating the Session!!")
  }
}

const registerUser = asyncHandler(async(req,res)=>{
  const {username,email,password} = req.body;
  if(!username || !email || !password){
    throw new ApiError(400,"All Fields are required!!")
  }

  const existedUser = await User.findOne({
    $or: [{username},{email}]
  });

  if(existedUser){
    throw new ApiError(409,"User Already Exists");
  }

  const now = new Date();


  const user = await User.create({
    username,
    email,
    password,
    otpLastSentAt: now,
    otpSendWindowStartedAt: now,
    otpSendCount: 1
  })

  const otp = generateOTP();
  const html = emailVerificationOtpTemplate(otp);

  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

  const otpModel = await OTP.create({
    email,
    user: user._id,
    otpHash:otp,
    purpose:"email-verification",
    expiresAt
  });

  await sendEmail(email,"Email Verification OTP",`Your OTP is ${otp}. It is valid for 5 minutes.`,html)

  return res
  .status(201)
  .json(new ApiResponse(201,"User Registered Successfully",{username,email,verified:user.verified}))
}); 

const login = asyncHandler(async(req,res)=>{
  const {username,email,password} = req.body;
  if(!username && !email){
    throw new ApiError(401,"Username or email is required!!");
  }

  if(!password){
    throw new ApiError(401,"Password is Required");
  }

  const user = await User.findOne({
    $or: [{username},{email}]
  });

  if(!user){
    throw new ApiError(401,"No User Found!!, Please Register");
  }

  if(!user.verified){
    throw new ApiError(401,"Please verify you Email to Login!!")
  }

  const isPasswordValid = await user.isPasswordCorrect(password);
  if(!isPasswordValid){
    throw new ApiError(401,"Incorrect Password")
  }

  const {accessToken,refreshToken} = await generateAccessandRefreshToken(user,req);

  const options = {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 7*24*60*60*1000 //7days
  }

  return res
  .status(200)
  .cookie("refreshToken",refreshToken,options)
  .json(new ApiResponse(200,"User LoggedIn Successfully!!",{
    username:user.username,
    email:user.email,
    accessToken
  }))

})

const getUser = asyncHandler(async(req,res)=>{
  const user = req?.user;

  if(!user){
    throw new ApiError(404,"User not found");
  }

  return res
  .status(200)
  .json(new ApiResponse(200,"User fetched Successfully!!",user));
})

const refreshAccessToken = asyncHandler(async(req,res)=>{
  const token = req.cookies?.refreshToken;
  
  if(!token){
    throw new ApiError(401,"Unauthorized Request,Please login again!!")
  }

  let decodedToken;

  try {
    decodedToken = jwt.verify(token,config.REFRESHTOKEN_SECRET);
  } catch (error) {
    throw new ApiError(401,"Invalid or expired refresh token")
  }

  const session = await Session.findOne({
    _id: decodedToken.sessionId,
    userId: decodedToken._id,
    revoked: false,
    expiresAt: {$gt: new Date()}
  });
  

  if(!session){
    throw new ApiError(401,"Session Expired or Revoked, Please login Again!!")
  }

  const isRefreshTokenValid = await bcrypt.compare(token,session.refreshTokenHash);
  
  if (!isRefreshTokenValid) {
    throw new ApiError(401, "Invalid or rotated refresh token");
  }

  const user = await User.findById(decodedToken._id);
  if(!user){
    throw new ApiError("User not Found!!");
  }

  const newAccessToken = await user.generateAccessToken(session._id)
  const newRefreshToken = await user.generateRefreshToken(session._id)

  session.refreshTokenHash = await bcrypt.hash(newRefreshToken,10);
  await session.save();

  const options = {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 7*24*60*60*1000 //7days
  }

  return res
  .status(200)
  .cookie("refreshToken",newRefreshToken,options)
  .json(new ApiResponse(200,"Access Token Refreshed Successfully!!",{accessToken:newAccessToken}))
})

const logout = asyncHandler(async(req,res)=>{
  const session = await Session.findByIdAndUpdate(req.session._id,{
    $set:{revoked:true}
  });

  if(!session){
    throw new ApiError(401,"Session revoked or expired")
  }

  const options = {
    httpOnly: true,
    secure: true,
  }

  return res
  .status(200)
  .clearCookie("refreshToken",options)
  .json(new ApiResponse(200,"User Logged out Successfully!!"))
});

const logoutAllDevice = asyncHandler(async(req,res)=>{
  const session = await Session.updateMany(
    {
      userId: req.user._id,
      revoked: false
    },
    {
      $set: { revoked: true}
    }
  );

  const options = {
    httpOnly: true,
    secure: true,
  }

  return res
  .status(200)
  .clearCookie("refreshToken",options)
  .json(new ApiResponse(200,"User Logged out from all Devices Successfully!!",{sessionRevoked:session.modifiedCount}))
})


const verifyEmail = asyncHandler(async (req, res) => {
  const { otp, email } = req.body;

  // 1. Validate request body
  if (!email || !otp) {
    throw new ApiError(400, "Email and OTP are required");
  }

  if (typeof otp !== "string" || !/^\d{6}$/.test(otp)) {
    throw new ApiError(400, "OTP must be a valid 6-digit code");
  }

  // 2. Find the latest OTP
  const otpModel = await OTP.findOne({
    email: email.trim().toLowerCase(),
    purpose: "email-verification"
  }).sort({ createdAt: -1 });

  if (!otpModel) {
    throw new ApiError(404, "OTP has expired or not found.");
  }

  // 3. Check expiration
  if (otpModel.expiresAt <= new Date()) {
    await OTP.deleteOne({ _id: otpModel._id });

    throw new ApiError(
      410,
      "OTP has expired. Please request a new OTP."
    );
  }

  // 4. Check maximum attempts
  if (otpModel.attempts >= MAX_OTP_SENDS) {
    throw new ApiError(
      429,
      "Maximum OTP attempts reached. Please request a new OTP."
    );
  }

  // 5. Verify OTP using bcrypt
  const isOtpValid = await otpModel.isOtpCorrect(otp);

  if (!isOtpValid) {
    const updatedOtp = await OTP.findOneAndUpdate(
      {
        _id: otpModel._id,
        attempts: { $lt: MAX_OTP_SENDS },
        expiresAt: { $gt: new Date() }
      },
      {
        $inc: { attempts: 1 }
      },
      { new: true }
    );

    if (!updatedOtp) {
      throw new ApiError(
        429,
        "Maximum OTP attempts reached or OTP expired."
      );
    }

    if (updatedOtp.attempts >= MAX_OTP_SENDS) {
      throw new ApiError(
        429,
        "Maximum OTP attempts reached. Please request a new OTP."
      );
    }

    throw new ApiError(401, "Invalid OTP");
  }

  // 6. Check whether the user exists
  const existingUser = await User.findById(otpModel.user);

  if (!existingUser) {
    await OTP.deleteMany({ user: otpModel.user });
    throw new ApiError(404, "User not found");
  }

  if (existingUser.verified) {
    await OTP.deleteMany({ user: otpModel.user });

    throw new ApiError(400, "Email is already verified");
  }

  // 7. Atomically consume the OTP
  const consumedOtp = await OTP.findOneAndDelete({
    _id: otpModel._id,
    attempts: { $lt: MAX_OTP_SENDS },
    expiresAt: { $gt: new Date() }
  });

  if (!consumedOtp) {
    throw new ApiError(
      409,
      "OTP has already been used or expired. Please try again."
    );
  }

  // 8. Mark the user as verified
  const user = await User.findByIdAndUpdate(
    consumedOtp.user,
    { verified: true },
    { new: true }
  ).select("-password");

  if (!user) {
    throw new ApiError(404, "User not found");
  }

  // 9. Delete any remaining OTP records
  await OTP.deleteMany({
    user: consumedOtp.user,
    purpose: "email-verification"
  });

  return res.status(200).json(
    new ApiResponse(
      200,
      "Email Verified Successfully",
      { user }
    )
  );
});


const resendOTP = asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new ApiError(400, "Email is required");
  }

  const user = await User.findOne({ email });

  if (!user) {
    throw new ApiError(404, "User not found");
  }

  if (user.verified) {
    throw new ApiError(400, "Email is already verified");
  }

  const now = new Date();

  const cooldownCutoff = new Date(now.getTime() - OTP_COOLDOWN);
  const windowCutoff = new Date(now.getTime() - OTP_WINDOW);

  // Atomically reserve an OTP send slot.
  // The hourly window resets when its starting time is older than 1 hour.
  const updatedUser = await User.findOneAndUpdate(
    {
      _id: user._id,
      verified: false,

      // Cooldown check
      otpLastSentAt: { $lte: cooldownCutoff },

      // Hourly limit check
      $or: [
        { otpSendWindowStartedAt: { $lte: windowCutoff } },
        { otpSendCount: { $lt: MAX_OTP_SENDS } }
      ]
    },
    [
      {
        $set: {
          otpSendCount: {
            $cond: [
              { $lte: ["$otpSendWindowStartedAt", windowCutoff] },
              1,
              { $add: ["$otpSendCount", 1] }
            ]
          },
          otpSendWindowStartedAt: {
            $cond: [
              { $lte: ["$otpSendWindowStartedAt", windowCutoff] },
              now,
              "$otpSendWindowStartedAt"
            ]
          },
          otpLastSentAt: now
        }
      }
    ],
    { 
      new: true,
      updatePipeline: true
    }
    
  );

  if (!updatedUser) {
    // Fetch latest values to identify why the request was rejected.
    const latestUser = await User.findById(user._id);

    if (!latestUser) {
      throw new ApiError(404, "User not found");
    }

    const cooldownRemaining =
      OTP_COOLDOWN - (now.getTime() - latestUser.otpLastSentAt.getTime());

    if (cooldownRemaining > 0) {
      throw new ApiError(
        429,
        `Please wait ${Math.ceil(cooldownRemaining / 1000)} seconds before requesting another OTP`
      );
    }

    throw new ApiError(
      429,
      "Maximum OTP resend limit reached. Please try again after one hour."
    );
  }

  // Generate new OTP
  const otp = generateOTP();
  const html = emailVerificationOtpTemplate(otp);
  const expiresAt = new Date(now.getTime() + OTP_EXPIRY);

  // Store the new OTP without deleting the previous one yet
  const newOtp = await OTP.create({
    email: user.email,
    user: user._id,
    otpHash: otp,
    purpose:"email-verification",
    expiresAt
  });

  // Try sending the new OTP
  try {
    await sendEmail(
      user.email,
      "Email Verification OTP",
      `Your OTP is ${otp}. It is valid for 5 minutes.`,
      html
    );
  } catch (error) {
    try {
      await OTP.deleteOne({ _id: newOtp._id });
    } catch (cleanupError) {
      console.error("Failed to clean up new OTP:", cleanupError);
    }

    throw error;
}

  // Email sent successfully: now remove previous OTPs
  await OTP.deleteMany({
    user: user._id,
    purpose: "email-verification",
    _id: { $ne: newOtp._id }
  });

  return res.status(200).json(
  new ApiResponse(200, "Email Verification OTP sent successfully", {
    email: user.email,
    expiresIn: OTP_EXPIRY / 1000,
    resendAfter: OTP_COOLDOWN / 1000
  })
);
});


const forgotPassword = asyncHandler(async (req, res) => {
  const { email } = req.body;

  if (!email) {
    throw new ApiError(400, "Email is required!!");
  }

  const existingUser = await User.findOne({
    email: email.trim().toLowerCase(),
    verified: true
  });

  if (!existingUser) {
    throw new ApiError(404, "User not Found!!");
  }

  const now = new Date();

  const cooldownCutoff = new Date(
    now.getTime() - OTP_COOLDOWN
  );

  const windowCutoff = new Date(
    now.getTime() - OTP_WINDOW
  );

  // 1. Apply password-reset rate limiting
  const updatedUser = await User.findOneAndUpdate(
    {
      _id: existingUser._id,
      verified: true,
      $or: [
        { passwordOtpLastSentAt: null },
        { passwordOtpLastSentAt: { $lte: cooldownCutoff } }
      ],
      $and: [
        {
          $or: [
            { passwordOtpWindowStartedAt: null },
            { passwordOtpWindowStartedAt: { $lte: windowCutoff } },
            { passwordOtpSendCount: { $lt: MAX_OTP_SENDS } }
          ]
        }
      ]
    },
    [
      {
        $set: {
          passwordOtpSendCount: {
            $cond: [
              {
                $or: [
                  { $eq: ["$passwordOtpWindowStartedAt", null] },
                  {
                    $lte: [
                      "$passwordOtpWindowStartedAt",
                      windowCutoff
                    ]
                  }
                ]
              },
              1,
              { $add: ["$passwordOtpSendCount", 1] }
            ]
          },

          passwordOtpWindowStartedAt: {
            $cond: [
              {
                $or: [
                  { $eq: ["$passwordOtpWindowStartedAt", null] },
                  {
                    $lte: [
                      "$passwordOtpWindowStartedAt",
                      windowCutoff
                    ]
                  }
                ]
              },
              now,
              "$passwordOtpWindowStartedAt"
            ]
          },

          passwordOtpLastSentAt: now
        }
      }
    ],
    {
      new: true,
      updatePipeline: true
    }
  );

  // 2. Handle rate-limit failure
  if (!updatedUser) {
    const latestUser = await User.findById(existingUser._id);

    const cooldownRemaining = latestUser.passwordOtpLastSentAt
      ? OTP_COOLDOWN -
        (now.getTime() - latestUser.passwordOtpLastSentAt.getTime())
      : 0;

    if (cooldownRemaining > 0) {
      throw new ApiError(
        429,
        `Please wait ${Math.ceil(cooldownRemaining / 1000)} seconds before requesting another OTP`
      );
    }

    throw new ApiError(
      429,
      "Maximum password-reset OTP requests reached. Please try again after one hour."
    );
  }

  // 3. Generate OTP
  const otp = generateOTP();
  const html = passwordResetOtpTemplate(otp);
  const expiresAt = new Date(now.getTime() + OTP_EXPIRY);

  const passwordOtp = await OTP.create({
    email: existingUser.email,
    user: existingUser._id,
    otpHash: otp,
    purpose: "password-reset",
    expiresAt
  });

  // 4. Send email
  try {
    await sendEmail(
      existingUser.email,
      "Password-Reset OTP",
      `Your OTP is ${otp}. It is valid for 5 minutes.`,
      html
    );
  } catch (error) {
    try {
      await OTP.deleteOne({ _id: passwordOtp._id });
    } catch (cleanupError) {
      console.error("Failed to clean up new OTP:", cleanupError);
    }

    throw error;
  }

  // 5. Delete previous password-reset OTPs
  await OTP.deleteMany({
    user: existingUser._id,
    purpose: "password-reset",
    _id: { $ne: passwordOtp._id }
  });

  return res.status(200).json(
    new ApiResponse(
      200,
      "Password-Reset OTP sent Successfully!!",
      {
        email: existingUser.email,
        expiresIn: Math.ceil(
          (expiresAt.getTime() - Date.now()) / 60000
        ),
        resendAfter: OTP_COOLDOWN / 1000
      }
    )
  );
});




const resetPassword = asyncHandler(async (req, res) => {
  const { email, otp, newPassword } = req.body;

  // 1. Validate request body
  if (!email || !otp || !newPassword) {
    throw new ApiError(
      400,
      "Email, OTP and new password are required!!"
    );
  }

  if (typeof otp !== "string" || !/^\d{6}$/.test(otp)) {
    throw new ApiError(400, "OTP must be a valid 6-digit code");
  }

  if (typeof newPassword !== "string" || newPassword.length < 8) {
    throw new ApiError(
      400,
      "Password must contain at least 8 characters"
    );
  }

  const normalizedEmail = email.trim().toLowerCase();

  // 2. Find the latest password-reset OTP
  const otpModel = await OTP.findOne({
    email: normalizedEmail,
    purpose: "password-reset"
  }).sort({ createdAt: -1 });

  if (!otpModel) {
    throw new ApiError(
      404,
      "Password-reset OTP not found. Please request a new OTP."
    );
  }

  // 3. Check OTP expiry
  if (otpModel.expiresAt <= new Date()) {
    await OTP.deleteOne({ _id: otpModel._id });

    throw new ApiError(
      410,
      "OTP has expired. Please request a new OTP."
    );
  }

  // 4. Check maximum attempts
  if (otpModel.attempts >= MAX_OTP_SENDS) {
    throw new ApiError(
      429,
      "Maximum OTP attempts reached. Please request a new OTP."
    );
  }

  // 5. Verify OTP
  const isOtpValid = await otpModel.isOtpCorrect(otp);

  if (!isOtpValid) {
    const updatedOtp = await OTP.findOneAndUpdate(
      {
        _id: otpModel._id,
        attempts: { $lt: MAX_OTP_SENDS },
        expiresAt: { $gt: new Date() }
      },
      {
        $inc: { attempts: 1 }
      },
      { new: true }
    );

    if (!updatedOtp) {
      throw new ApiError(
        429,
        "Maximum OTP attempts reached or OTP expired."
      );
    }

    if (updatedOtp.attempts >= MAX_OTP_SENDS) {
      throw new ApiError(
        429,
        "Maximum OTP attempts reached. Please request a new OTP."
      );
    }

    throw new ApiError(401, "Invalid OTP");
  }

  // 6. Find the user
  const existingUser = await User.findById(otpModel.user);

  if (!existingUser) {
    await OTP.deleteMany({
      user: otpModel.user,
      purpose: "password-reset"
    });

    throw new ApiError(404, "User not found");
  }

  // 7. Atomically consume the OTP
  const consumedOtp = await OTP.findOneAndDelete({
    _id: otpModel._id,
    purpose: "password-reset",
    attempts: { $lt: MAX_OTP_SENDS },
    expiresAt: { $gt: new Date() }
  });

  if (!consumedOtp) {
    throw new ApiError(
      409,
      "OTP has already been used or expired. Please try again."
    );
  }

  // 8. Update the password
  existingUser.password = newPassword;
  await existingUser.save();

  // 9. Delete any remaining password-reset OTPs
  await OTP.deleteMany({
    user: existingUser._id,
    purpose: "password-reset"
  });

  // 10. Revoke existing sessions
  await Session.deleteMany({
    userId: existingUser._id
  });

  return res.status(200).json(
    new ApiResponse(
      200,
      "Password reset successfully!!",
      {
        email: existingUser.email
      }
    )
  );
});


export {
  registerUser,
  getUser,
  refreshAccessToken,
  logout,
  logoutAllDevice,
  login,
  verifyEmail,
  resendOTP,
  forgotPassword,
  resetPassword
}