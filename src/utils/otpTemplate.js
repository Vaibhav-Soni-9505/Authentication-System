export const generateOTP = ()=>{
  return Math.floor(100000 + Math.random() * 900000).toString();
}

export const otpTemplate = (otp) => {
  return `
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Email Verification</title>
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

          <h2 style="color: #333;">Email Verification</h2>

          <p style="color: #666;">
            Thank you for registering!
            Use the OTP below to verify your email address.
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
            If you did not request this verification,
            please ignore this email.
          </p>

        </div>

      </body>
    </html>
  `;
};