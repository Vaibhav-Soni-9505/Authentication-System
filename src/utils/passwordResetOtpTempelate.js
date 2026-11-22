export const passwordResetOtpTemplate = (otp) => {
  return `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Reset your password</title>
      </head>

      <body style="
        margin: 0;
        padding: 30px;
        background-color: #f4f4f4;
        font-family: Arial, sans-serif;
      ">

        <div style="
          max-width: 500px;
          margin: auto;
          padding: 30px;
          background-color: #ffffff;
          border-radius: 10px;
          text-align: center;
        ">

          <h2 style="color: #333;">Reset Your Password</h2>

          <p style="color: #666;">
            We received a request to reset your account password. Use the following OTP to continue.
          </p>

          <div style="
            margin: 25px 0;
            padding: 15px;
            background-color: #f1f1f1;
            border-radius: 8px;
            font-size: 30px;
            font-weight: bold;
            letter-spacing: 8px;
            color: #222;
          ">
            ${otp}
          </div>

          <p style="color: #777;">
            This OTP is valid for 5 minutes.
          </p>

          <p style="color: #999; font-size: 12px;">
            If you did not request a password reset, please ignore this email. Your existing password will remain unchanged.
          </p>

        </div>

      </body>
    </html>
  `;
};