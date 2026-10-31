import mongoose,{Schema} from "mongoose"
import bcrypt from "bcrypt"

const otpSchema = new Schema({
  email:{
    type: String,
    required: [true,"Email is required!!"]
  },
  user:{
    type: Schema.Types.ObjectId,
    ref: "User",
    required: [true,"User is required!!"]
  },
  otpHash:{
    type: String,
    required:[true,"OTP is required!!"]
  },
  expiresAt: {
    type: Date,
    required: true
  },
  attempts: {
    type: Number,
    default: 0
  }
},{timestamps:true})

otpSchema.pre("save",async function(){
  if (!this.isModified("otpHash")) return;
  this.otpHash = await bcrypt.hash(this.otpHash,10)
});

otpSchema.methods.isOtpCorrect = async function(otp){
  return await bcrypt.compare(otp,this.otpHash)
}

otpSchema.index(
  { expiresAt: 1 },
  { expireAfterSeconds: 0 }
);

export const OTP = mongoose.model("OTP",otpSchema)