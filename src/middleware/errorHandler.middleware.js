const errorHandler = (err,req,res,next)=>{
  const status = err.status || 500;

  res.status(status).json({
    sucess: false,
    message : err.message || "Internal Servor Error",
    data : null,
    errors: err.errors || []
  })
}

export {errorHandler};