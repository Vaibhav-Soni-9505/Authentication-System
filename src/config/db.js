import mongoose from "mongoose";
import config from "../config/config.js";

const connectDB = async()=>{
  try {
    const connectionInstance = await mongoose.connect(`${config.MONGODB_URI}/auth`);
    console.log(`MongoDB connected!! DB HOST: ${connectionInstance.connection.host}`);
  } catch (error) {
    console.log("MONGODB Connection Failed:",error);
    process.exit(1)
  }
}

export default connectDB;