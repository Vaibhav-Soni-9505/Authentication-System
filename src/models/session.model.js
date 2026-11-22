import mongoose,{Schema} from "mongoose";

const sessionSchema = new Schema({
  userId: {
    type: Schema.Types.ObjectId,
    ref: "User",
    required: [true,"UserId is required!!"]
  },

  refreshTokenHash: {
    type: String,
    required: [true,"Refresh Token is Required!!"]
  },

  ip:{
    type: String,
    required: [true,""]
  },

  userAgent:{
    type: String,
    required:[true,"User agent is required!!"]
  },

  revoked: {
    type: Boolean,
    default: false
  },

  expiresAt:{
    type: Date,
    required: true
  }

},{timestamps:true})

sessionSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0 }
);


export const Session = mongoose.model("Session",sessionSchema);