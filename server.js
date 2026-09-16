```javascript
const express = require("express");
const crypto = require("crypto");

const app = express();

const PORT = process.env.PORT || 3000;

// ============================================
// MIDDLEWARE
// ============================================

app.use(express.json());

// ============================================
// CORS
// ============================================

app.use((req, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader(
        "Access-Control-Allow-Methods",
        "GET,POST,OPTIONS"
    );
    res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type"
    );

    if (req.method === "OPTIONS") {
        return res.sendStatus(204);
    }

    next();
});

// ============================================
// TEMPORARY OTP STORAGE
// ============================================

const otpStore = new Map();

// ============================================
// PHILIPPINE PHONE NUMBER
// ============================================

function normalizePhilippineNumber(phone) {
    let number = String(phone || "")
        .trim()
        .replace(/[\s()-]/g, "");

    // +639XXXXXXXXX -> 639XXXXXXXXX
    if (number.startsWith("+63")) {
        number = number.substring(1);
    }

    // 09XXXXXXXXX -> 639XXXXXXXXX
    if (number.startsWith("09")) {
        number = "63" + number.substring(1);
    }

    return number;
}

function isValidPhilippineNumber(phone) {
    return /^639\d{9}$/.test(phone);
}

// ============================================
// SECURE OTP GENERATOR
// ============================================

function generateOTP() {
    return crypto
        .randomInt(100000, 1000000)
        .toString();
}

// ============================================
// HEALTH CHECK
// ============================================

app.get("/", (req, res) => {
    res.status(200).json({
        success: true,
        message: "Attendance OTP server is running."
    });
});

// ============================================
// SEND OTP
// ============================================

app.post(
    "/api/auth/forgot-password",
    async (req, res) => {

        try {

            const phone =
                normalizePhilippineNumber(
                    req.body?.phone
                );

            // --------------------------------
            // Validate phone
            // --------------------------------

            if (!isValidPhilippineNumber(phone)) {
                return res.status(400).json({
                    success: false,
                    message:
                        "Enter a valid Philippine mobile number."
                });
            }

            // --------------------------------
            // Semaphore API key
            // --------------------------------

            const apiKey =
                process.env.SEMAPHORE_API_KEY;

            if (!apiKey) {

                console.error(
                    "SEMAPHORE_API_KEY is missing."
                );

                return res.status(500).json({
                    success: false,
                    message:
                        "SMS service is not configured on the server."
                });
            }

            // --------------------------------
            // Generate OTP
            // --------------------------------

            const otp = generateOTP();

            const expiresAt =
                Date.now() + (5 * 60 * 1000);

            // --------------------------------
            // Store OTP
            // --------------------------------

            otpStore.set(phone, {
                otp: otp,
                expiresAt: expiresAt,
                attempts: 0
            });

            console.log(
                `Preparing OTP for ${phone}`
            );

            // --------------------------------
            // SEND SMS THROUGH SEMAPHORE
            // --------------------------------

            const semaphoreResponse =
                await fetch(
                    "https://api.semaphore.co/api/v4/otp",
                    {
                        method: "POST",

                        headers: {
                            "Content-Type":
                                "application/x-www-form-urlencoded"
                        },

                        body:
                            new URLSearchParams({
                                apikey: apiKey,
                                number: phone,

                                message:
                                    "Your Attendance System password reset code is {otp}. It expires in 5 minutes.",

                                code: otp
                            })
                    }
                );

            // --------------------------------
            // Read response
            // --------------------------------

            const responseText =
                await semaphoreResponse.text();

            let semaphoreResult;

            try {
                semaphoreResult =
                    JSON.parse(responseText);
            } catch {
                semaphoreResult =
                    responseText;
            }

            console.log(
                "Semaphore response:",
                semaphoreResult
            );

            // --------------------------------
            // HTTP ERROR
            // --------------------------------

            if (!semaphoreResponse.ok) {

                otpStore.delete(phone);

                return res.status(502).json({
                    success: false,
                    message:
                        "Semaphore could not send the SMS."
                });
            }

            // --------------------------------
            // CHECK PROVIDER STATUS
            // --------------------------------

            let providerFailed = false;

            if (Array.isArray(semaphoreResult)) {

                const firstResult =
                    semaphoreResult[0];

                if (
                    firstResult &&
                    (
                        firstResult.status === "Failed" ||
                        firstResult.status === "failed" ||
                        firstResult.status === "Error" ||
                        firstResult.status === "error"
                    )
                ) {
                    providerFailed = true;
                }

            } else if (
                semaphoreResult &&
                typeof semaphoreResult === "object"
            ) {

                if (
                    semaphoreResult.status === "Failed" ||
                    semaphoreResult.status === "failed" ||
                    semaphoreResult.status === "Error" ||
                    semaphoreResult.status === "error"
                ) {
                    providerFailed = true;
                }
            }

            // --------------------------------
            // PROVIDER REJECTED SMS
            // --------------------------------

            if (providerFailed) {

                otpStore.delete(phone);

                return res.status(502).json({
                    success: false,
                    message:
                        "The SMS provider rejected the message."
                });
            }

            // --------------------------------
            // SUCCESS
            // --------------------------------

            console.log(
                `OTP request accepted for ${phone}`
            );

            return res.status(200).json({
                success: true,
                message:
                    "OTP sent successfully."
            });

        } catch (error) {

            console.error(
                "SEND OTP ERROR:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Internal server error while sending OTP."
            });
        }
    }
);

// ============================================
// VERIFY OTP
// ============================================

app.post(
    "/api/auth/verify-reset",
    async (req, res) => {

        try {

            const phone =
                normalizePhilippineNumber(
                    req.body?.phone
                );

            const otp =
                String(
                    req.body?.otp || ""
                ).trim();

            const newPassword =
                String(
                    req.body?.newPassword || ""
                );

            // --------------------------------
            // Validate phone
            // --------------------------------

            if (!isValidPhilippineNumber(phone)) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Invalid Philippine mobile number."
                });
            }

            // --------------------------------
            // Validate OTP
            // --------------------------------

            if (!/^\d{6}$/.test(otp)) {

                return res.status(400).json({
                    success: false,
                    message:
                        "OTP must contain exactly 6 digits."
                });
            }

            // --------------------------------
            // Validate password
            // --------------------------------

            if (
                newPassword.length < 8 ||
                newPassword.length > 128
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "Password must be between 8 and 128 characters."
                });
            }

            // --------------------------------
            // Find OTP
            // --------------------------------

            const savedOTP =
                otpStore.get(phone);

            if (!savedOTP) {

                return res.status(400).json({
                    success: false,
                    message:
                        "OTP expired or not found. Request a new OTP."
                });
            }

            // --------------------------------
            // Check expiration
            // --------------------------------

            if (
                Date.now() >
                savedOTP.expiresAt
            ) {

                otpStore.delete(phone);

                return res.status(400).json({
                    success: false,
                    message:
                        "OTP has expired. Request a new OTP."
                });
            }

            // --------------------------------
            // Limit attempts
            // --------------------------------

            if (
                savedOTP.attempts >= 5
            ) {

                otpStore.delete(phone);

                return res.status(429).json({
                    success: false,
                    message:
                        "Too many incorrect OTP attempts. Request a new OTP."
                });
            }

            // --------------------------------
            // Check OTP
            // --------------------------------

            if (
                savedOTP.otp !== otp
            ) {

                savedOTP.attempts++;

                return res.status(400).json({
                    success: false,
                    message:
                        "Incorrect OTP."
                });
            }

            // --------------------------------
            // OTP VERIFIED
            // --------------------------------

            otpStore.delete(phone);

            console.log(
                `OTP verified successfully for ${phone}`
            );

            return res.status(200).json({
                success: true,
                message:
                    "OTP verified successfully."
            });

        } catch (error) {

            console.error(
                "VERIFY OTP ERROR:",
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    "Internal server error while verifying OTP."
            });
        }
    }
);

// ============================================
// START SERVER
// ============================================

app.listen(
    PORT,
    "0.0.0.0",
    () => {

        console.log(
            `Attendance OTP server running on port ${PORT}`
        );

    }
);
```
