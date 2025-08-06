import appError from "./../utils/AppError.js";

const handleDupErr = (err) => {
  const emailMatch = err.message.match(
    /'([\w.-]+@[a-zA-Z\d.-]+\.[a-zA-Z]{2,})'/
  );
  const message = `This email ${emailMatch?.[0] || ""} is already registered.`;
  return new appError(message, 400);
};

const sentErrorDev = (res, err) => {
  return res.status(err.statusCode).json({
    message: err.message,
    error: err,
    status: err.status,
    errStack: err.stack,
  });
};

const sentErrorPro = (res, err) => {
  if (err.isOperational) {
    return res.status(err.statusCode).json({
      message: err.message,
      status: err.status,
    });
  } else {
    console.error("error: ", err);
    return res.status(500).json({
      message: "Something went wrong!",
    });
  }
};

const errorHandler = (err, req, res, next) => {
  err.statusCode = err.statusCode || 500;
  err.status = err.status || "Server Error";

  if (process.env.NODE_EV === "development") {
    sentErrorDev(res, err);
  } else if (process.env.NODE_EV === "production") {
    if (err.code === "ER_DUP_ENTRY") {
      err = handleDupErr(err);
    }
    sentErrorPro(res, err);
  }
};

export default errorHandler;

