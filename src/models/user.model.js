import mongoose,{Schema} from "mongoose"
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import config from "../config/config.js";

const userSchema = new Schema({
  username:{
    type: String,
    required: [true,"Username is Required"],
    unique: [true,"Username must be unique"]
  },
  email:{
    type: String,
    required: [true,"Email is Required"],
    unique: [true,"Email must be unique"]
  },
  password:{
    type: String,
    required: [true,"Password is Required"]
  },
  verified:{
    type: Boolean,
    default: false
  },
  otpLastSentAt: {
    type: Date,
    default: null
  },
  otpSendWindowStartedAt: {
    type: Date,
    default: null
  },
  otpSendCount: {
    type: Number,
    default: 0
  },
  passwordOtpLastSentAt: {
    type: Date,
    default: null
  },
  passwordOtpWindowStartedAt: {
    type: Date,
    default: null
  },
  passwordOtpSendCount: {
    type: Number,
    default: 0
  }
});

userSchema.pre("save",async function(){
  if(!this.isModified("password")) return
  this.password = await bcrypt.hash(this.password,10)
})

userSchema.methods.isPasswordCorrect = async function(password) {
  return await bcrypt.compare(password,this.password);
}

userSchema.methods.generateAccessToken = function(sessionId) {
  return jwt.sign(
    {
      _id:this._id,
      sessionId,
      tokenType: "access"
    },
    config.ACCESSTOKEN_SECRET,
    {
      expiresIn: "5m"
    }
  )
}

userSchema.methods.generateRefreshToken = function(sessionId) {
  return jwt.sign(
    {
      _id:this._id,
      sessionId,
      tokenType: "refresh"
    },
    config.REFRESHTOKEN_SECRET,
    {
      expiresIn: "7d"
    }
  )
}

export const User = mongoose.model("User",userSchema)