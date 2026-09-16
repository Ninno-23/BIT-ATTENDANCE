const express = require("express");

const app = express();

app.use(express.json());

const PORT = process.env.PORT || 3000;

// Temporary OTP storage
const otpStore = new Map();

function normalizePhilippineNumber(phone) {
  let number = String(phone || "").replace(/[\s()-]/g, "");

  if (number.startsWith("09")) {
    number = "63" + number.substring(1);
  } else if (number.startsWith("+63")) {
    number = number.substring(1);
  }

  return number;
}

function isValidPhilippineNumber(phone) {
  return /^639\d{9}$/.test(phone);
}


// ==============================
// SERVER TEST
// ==============================

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Attendance OTP server is running."
  });
});


// ==============================
// SEND OTP
// ==============================

app.post("/api/auth/forgot-password", async (req, res) => {
  try {

    const { phone } = req.body || {};

    const normalizedPhone =
      normalizePhilippineNumber(phone);

    if (!isValidPhilippineNumber(normalizedPhone)) {
      return res.status(400).json({
        success: false,
        message: "Enter a valid Philippine mobile number."
      });
    }

    if (!process.env.SEMAPHORE_API_KEY) {

      console.error(
        "SEMAPHORE_API_KEY is missing."
      );

      return res.status(500).json({
        success: false,
        message: "SMS service is not configured."
      });
    }


    // Generate 6-digit OTP
    const otp = Math.floor(
      100000 + Math.random() * 900000
    ).toString();


    // Store OTP for 5 minutes
    otpStore.set(normalizedPhone, {
      otp: otp,
      expiresAt: Date.now() + (5 * 60 * 1000)
    });


    // Send SMS using Semaphore
    const response = await fetch(
      "https://api.semaphore.co/api/v4/messages",
      {
        method: "POST",

        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },

        body: new URLSearchParams({
          apikey: process.env.SEMAPHORE_API_KEY,

          number: normalizedPhone,

          message:
            `Your password reset code is ${otp}. It expires in 5 minutes.`
        })
      }
    );


    const result = await response.json();


    if (!response.ok) {

      console.error(
        "Semaphore error:",
        result
      );

      otpStore.delete(normalizedPhone);

      return res.status(502).json({
        success: false,
        message:
          "SMS provider failed to send the OTP."
      });
    }


    console.log(
      `OTP sent to ${normalizedPhone}`
    );


    return res.status(200).json({
      success: true,
      message: "OTP sent successfully."
    });


  } catch (error) {

    console.error(
      "Forgot password error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Server error."
    });
  }
});


// ==============================
// VERIFY OTP
// ==============================

app.post("/api/auth/verify-reset", async (req, res) => {

  try {

    const {
      phone,
      otp,
      newPassword
    } = req.body || {};


    const normalizedPhone =
      normalizePhilippineNumber(phone);


    if (!isValidPhilippineNumber(normalizedPhone)) {

      return res.status(400).json({
        success: false,
        message:
          "Invalid Philippine mobile number."
      });
    }


    if (!/^\d{6}$/.test(String(otp || ""))) {

      return res.status(400).json({
        success: false,
        message:
          "OTP must contain 6 digits."
      });
    }


    if (!newPassword ||
        newPassword.length < 8) {

      return res.status(400).json({
        success: false,
        message:
          "Password must be at least 8 characters."
      });
    }


    const saved =
      otpStore.get(normalizedPhone);


    if (!saved) {

      return res.status(400).json({
        success: false,
        message:
          "OTP expired or not found."
      });
    }


    if (Date.now() > saved.expiresAt) {

      otpStore.delete(normalizedPhone);

      return res.status(400).json({
        success: false,
        message:
          "OTP has expired."
      });
    }


    if (String(saved.otp) !== String(otp)) {

      return res.status(400).json({
        success: false,
        message:
          "Incorrect OTP."
      });
    }


    // OTP is correct
    otpStore.delete(normalizedPhone);


    return res.status(200).json({
      success: true,
      message:
        "OTP verified successfully."
    });


  } catch (error) {

    console.error(
      "Verify reset error:",
      error
    );

    return res.status(500).json({
      success: false,
      message: "Server error."
    });
  }

});


// ==============================
// START SERVER
// ==============================

app.listen(PORT, () => {

  console.log(
    `OTP server running on port ${PORT}`
  );

});
