import dotenv from "dotenv"

dotenv.config();

const config = {
  MONGODB_URI: process.env.MONGODB_URI,
  PORT: process.env.PORT,
  ACCESSTOKEN_SECRET: process.env.ACCESSTOKEN_SECRET,
  REFRESHTOKEN_SECRET: process.env.REFRESHTOKEN_SECRET,
  GOOGLE_CLIENT_ID:process.env.GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET:process.env.GOOGLE_CLIENT_SECRET,
  GOOGLE_REFRESH_TOKEN:process.env.GOOGLE_REFRESH_TOKEN,
  GOOGLE_USER:process.env.GOOGLE_USER
}

export default config;