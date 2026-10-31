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
import { generateOTP, otpTemplate } from "../utils/otpTemplate.js";
import { OTP } from "../models/otp.model.js";


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
    throw new ApiError(402,"All Fields are required!!")
  }

  const existedUser = await User.findOne({
    $or: [{username},{email}]
  });

  if(existedUser){
    throw new ApiError(409,"User Already Exists");
  }

  const user = await User.create({
    username,
    email,
    password
  })

  const otp = generateOTP();
  const html = otpTemplate(otp);

  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

  const otpModel = await OTP.create({
    email,
    user: user._id,
    otpHash:otp,
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
  .status(201)
  .cookie("refreshToken",refreshToken,options)
  .json(new ApiResponse(201,"User LoggedIn Successfully!!",{username,email,accessToken}))

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

  const decodedToken = jwt.verify(token,config.REFRESHTOKEN_SECRET);
  if(!decodedToken){
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
    throw new ApiError("Session revoked or expired")
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

const verifyEmail = asyncHandler(async(req,res)=>{
  const {otp,email} = req.body;

  const otpModel = await OTP.findOne({email});
  if(!otpModel){
    throw new ApiError(404,"OTP has expired, or not found.")
  }

  if(otpModel.expiresAt <= new Date()){
    await OTP.deleteOne({
      _id: otpModel._id
    });

    throw new ApiError(410,"OTP has expired. Please request a new OTP.")
  }

  const MAX_ATTEMPTS = 5;

  if (otpModel.attempts >= MAX_ATTEMPTS) {
    throw new ApiError(429, "Maximum OTP attempts reached. Please request a new OTP.");
  }

  const isOtpValid = await otpModel.isOtpCorrect(otp);

  if (!isOtpValid) {
    const updatedOtp = await OTP.findOneAndUpdate(
      {
        _id: otpModel._id,
        attempts: { $lt: MAX_ATTEMPTS },
        expiresAt: { $gt: new Date() }
      },
      {
        $inc: { attempts: 1 }
      },
      { new: true }
    );

    if (!updatedOtp) {
      throw new ApiError(429, "Maximum OTP attempts reached or OTP expired.");
    }

    throw new ApiError(401, "Invalid OTP");
  }

  const user = await User.findByIdAndUpdate(otpModel.user,
    {verified: true},
    {new: true}
  ).select("-password");

  await OTP.deleteMany({
    user: otpModel.user
  });

  return res
  .status(200)
  .json(new ApiResponse(200,"Email Verified Successfully",{user}))
})

export {
  registerUser,
  getUser,
  refreshAccessToken,
  logout,
  logoutAllDevice,
  login,
  verifyEmail
}