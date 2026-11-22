import config from "./src/config/config.js";
import app from "./src/app.js"
import connectDB from "./src/config/db.js";

connectDB()
.then(()=>{
    app.listen(config.PORT || 3000,()=>{
    console.log(`Server is listening on Port ${config.PORT}`);
  })
})
.catch((err)=>{
  console.log("MongoDB connection failed!!",err);
  
})



