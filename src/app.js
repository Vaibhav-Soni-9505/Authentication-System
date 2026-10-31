import express from "express"
import morgan from "morgan"
import cookieParser from "cookie-parser";

const app = express();

app.use(express.json());
app.use(morgan("dev"));
app.use(cookieParser())

//import routes
import userRouter from "./routes/user.routes.js"
import { errorHandler } from "./middleware/errorHandler.middleware.js";

//routes declaration
app.use("/api/v1/users",userRouter)

app.use(errorHandler)
export default app;