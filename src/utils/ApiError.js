class ApiError extends Error{
  constructor(status,message="Something went wrong",errors=[]){
    super(message)
    this.status = status;
    this.message = message;
    this.errors = errors;
    this.data = null;
    this.success = false;
  }
}

export {ApiError}