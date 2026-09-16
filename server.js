// ============================================
// ATTENDANCE SYSTEM - FORGOT PASSWORD OTP
// ============================================

const App = {

    // ========================================
    // FORGOT PASSWORD FORM
    // ========================================

    showForgotPassword(show) {

        const forgotForm =
            document.getElementById("forgotPasswordForm");

        if (!forgotForm) {
            console.error(
                "forgotPasswordForm was not found."
            );
            return;
        }

        if (show) {

            forgotForm.classList.remove("hidden");

            const step1 =
                document.getElementById("resetStep1");

            const step2 =
                document.getElementById("resetStep2");

            const notice =
                document.getElementById("resetNotice");

            if (step1) {
                step1.classList.remove("hidden");
            }

            if (step2) {
                step2.classList.add("hidden");
            }

            if (notice) {
                notice.textContent = "";
            }

        } else {

            forgotForm.classList.add("hidden");

            const step1 =
                document.getElementById("resetStep1");

            const step2 =
                document.getElementById("resetStep2");

            const notice =
                document.getElementById("resetNotice");

            if (step1) {
                step1.classList.remove("hidden");
            }

            if (step2) {
                step2.classList.add("hidden");
            }

            if (notice) {
                notice.textContent = "";
            }
        }
    },


    // ========================================
    // SEND OTP
    // ========================================

    requestResetCode: async function () {

        const phoneInput =
            document.getElementById("resetPhone");

        const notice =
            document.getElementById("resetNotice");

        if (!phoneInput || !notice) {

            console.error(
                "Forgot password elements are missing."
            );

            return;
        }


        const phone =
            phoneInput.value.trim();


        if (!phone) {

            notice.textContent =
                "Please enter your recovery phone number.";

            return;
        }


        // Remove spaces, brackets and hyphens
        const normalizedPhone =
            phone.replace(/[\s()-]/g, "");


        // Philippine number validation
        const validPH =
            /^09\d{9}$/.test(normalizedPhone) ||
            /^\+639\d{9}$/.test(normalizedPhone);


        if (!validPH) {

            notice.textContent =
                "Enter a valid Philippine mobile number.";

            return;
        }


        notice.textContent =
            "Sending OTP...";


        try {

            const response = await fetch(
                "https://bit-attendance.onrender.com",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        phone: normalizedPhone
                    })
                }
            );


            let result;

            try {
                result = await response.json();
            } catch {

                result = {
                    success: false,
                    message:
                        "The server returned an invalid response."
                };
            }


            if (!response.ok || !result.success) {

                notice.textContent =
                    result.message ||
                    "Unable to send OTP.";

                return;
            }


            notice.textContent =
                "OTP sent successfully. Check your phone.";


            // Move to OTP step
            const step1 =
                document.getElementById("resetStep1");

            const step2 =
                document.getElementById("resetStep2");

            if (step1) {
                step1.classList.add("hidden");
            }

            if (step2) {
                step2.classList.remove("hidden");
            }


            // Clear previous values
            const otpInput =
                document.getElementById("smsCodeInput");

            const passwordInput =
                document.getElementById("newPasswordInput");

            const confirmPasswordInput =
                document.getElementById(
                    "confirmPasswordInput"
                );

            if (otpInput) {
                otpInput.value = "";
            }

            if (passwordInput) {
                passwordInput.value = "";
            }

            if (confirmPasswordInput) {
                confirmPasswordInput.value = "";
            }


            // Put cursor in OTP field
            if (otpInput) {
                otpInput.focus();
            }


        } catch (error) {

            console.error(
                "Send OTP error:",
                error
            );

            notice.textContent =
                "Could not connect to the OTP server.";
        }
    },


    // ========================================
    // VERIFY OTP AND RESET PASSWORD
    // ========================================

    submitPasswordReset: async function () {

        const phoneInput =
            document.getElementById("resetPhone");

        const otpInput =
            document.getElementById("smsCodeInput");

        const passwordInput =
            document.getElementById("newPasswordInput");

        const confirmPasswordInput =
            document.getElementById(
                "confirmPasswordInput"
            );

        const notice =
            document.getElementById("resetNotice");


        if (
            !phoneInput ||
            !otpInput ||
            !passwordInput ||
            !confirmPasswordInput ||
            !notice
        ) {

            console.error(
                "Password reset elements are missing."
            );

            return;
        }


        const phone =
            phoneInput.value.trim();

        const otp =
            otpInput.value.trim();

        const newPassword =
            passwordInput.value;

        const confirmPassword =
            confirmPasswordInput.value;


        // ====================================
        // VALIDATE OTP
        // ====================================

        if (!/^\d{6}$/.test(otp)) {

            notice.textContent =
                "Enter the 6-digit OTP.";

            otpInput.focus();

            return;
        }


        // ====================================
        // VALIDATE PASSWORD
        // ====================================

        if (newPassword.length < 8) {

            notice.textContent =
                "Password must be at least 8 characters.";

            passwordInput.focus();

            return;
        }


        // ====================================
        // CONFIRM PASSWORD
        // ====================================

        if (newPassword !== confirmPassword) {

            notice.textContent =
                "Passwords do not match.";

            confirmPasswordInput.focus();

            return;
        }


        notice.textContent =
            "Verifying OTP...";


        try {

            const response = await fetch(
                "https://attendance-otp-server.onrender.com/api/auth/verify-reset",
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({

                        phone: phone,

                        otp: otp,

                        newPassword:
                            newPassword

                    })
                }
            );


            let result;

            try {
                result = await response.json();
            } catch {

                result = {
                    success: false,
                    message:
                        "The server returned an invalid response."
                };
            }


            if (!response.ok || !result.success) {

                notice.textContent =
                    result.message ||
                    "OTP verification failed.";

                return;
            }


            notice.textContent =
                "OTP verified successfully.";


            /*
             * IMPORTANT:
             *
             * The current Render server verifies
             * the OTP, but it does NOT yet save
             * the new password to your instructor
             * account database.
             *
             * We will connect that after the
             * OTP system is confirmed working.
             */


            otpInput.value = "";
            passwordInput.value = "";
            confirmPasswordInput.value = "";


        } catch (error) {

            console.error(
                "Password reset error:",
                error
            );

            notice.textContent =
                "Could not connect to the OTP server.";
        }
    }

};


// ============================================
// MAKE APP AVAILABLE TO HTML
// ============================================

window.App = App;
