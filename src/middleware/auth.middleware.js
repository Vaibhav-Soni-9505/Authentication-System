import config from "../config/config.js";
import { Session } from "../models/session.model.js";
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import jwt from "jsonwebtoken"


const verifyjwt = asyncHandler(async(req,res,next)=>{
  try {
    const accessToken = req.headers?.authorization?.split(" ")[1];
    if(!accessToken){
      throw new ApiError(401,"Unauthorized Request, Access token not found")
    }
  
    const decodedToken = jwt.verify(accessToken,config.ACCESSTOKEN_SECRET);
    if(!decodedToken){
      throw new ApiError(401,"Invalid or expired access token")
    }
  
    const session = await Session.findOne({
        _id: decodedToken.sessionId,
        userId: decodedToken._id,
        revoked: false,
        expiresAt: { $gt: new Date() },
    });
    
    if (!session) {
      throw new ApiError(401, "Session expired or revoked");
    }
  
    const user = await User.findById(decodedToken._id).select("-password");
    if(!user){
      throw new ApiError(401,"User not found");
    }
  
    req.user = user;
    req.session = session;
  
    next()
  } catch (error) {
    throw new ApiError(401,error.message || "Invalid Access Token!!");
  }
});

export {verifyjwt};