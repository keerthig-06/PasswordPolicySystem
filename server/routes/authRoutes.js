
const express = require("express");
const bcrypt = require("bcryptjs");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const User = require("../models/User");

const router = express.Router();


// EMAIL CONFIGURATION

async function sendOTPEmail(email, otp) {

    const transporter = nodemailer.createTransport({

        service: "gmail",

        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_APP_PASSWORD
        }

    });

    await transporter.sendMail({

        from: process.env.EMAIL_USER,
        to: email,
        subject: "Password Reset OTP",

        text: `Your password reset OTP is ${otp}. It is valid for 5 minutes. Do not share this OTP with anyone.`

    });

}


// DFA PASSWORD VALIDATION

function validatePasswordDFA(password) {

    if (typeof password !== "string") {
        return false;
    }

    let state = 0;

    const specialCharacters = '!@#$%^&*(),.?":{}|<>';

    for (let i = 0; i < password.length; i++) {

        const ch = password[i];

        if (
            ch === "\n" ||
            ch === "\r" ||
            ch === "\u2028" ||
            ch === "\u2029"
        ) {
            return false;
        }

        let length = Math.floor(state / 16);
        let mask = state % 16;

        if (ch >= "A" && ch <= "Z") {
            mask |= 1;
        }

        if (ch >= "a" && ch <= "z") {
            mask |= 2;
        }

        if (ch >= "0" && ch <= "9") {
            mask |= 4;
        }

        if (specialCharacters.includes(ch)) {
            mask |= 8;
        }

        length = Math.min(length + 1, 8);

        state = length * 16 + mask;
    }

    return state >= 128 && state % 16 === 15;
}


// USER REGISTRATION

router.post("/register", async (req, res) => {

    try {

        const {
            username,
            email,
            password,
            confirmPassword
        } = req.body;

        if (!username || !email || !password || !confirmPassword) {

            return res.status(400).json({
                message: "All fields are required"
            });

        }

        if (!validatePasswordDFA(password)) {

            return res.status(400).json({
                message: "Password does not satisfy the policy"
            });

        }

        if (password !== confirmPassword) {

            return res.status(400).json({
                message: "Passwords do not match"
            });

        }

        const existingUser = await User.findOne({ email });

        if (existingUser) {

            return res.status(400).json({
                message: "Email already registered"
            });

        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({

            username,
            email,
            password: hashedPassword,
            accountStatus: "Registered"

        });

        await newUser.save();

        res.status(201).json({

            message: "Registration successful",

            user: {
                id: newUser._id,
                username: newUser.username,
                email: newUser.email,
                accountStatus: newUser.accountStatus
            }

        });

    } catch (error) {

        res.status(500).json({
            message: "Registration failed",
            error: error.message
        });

    }

});


// USER LOGIN

router.post("/login", async (req, res) => {

    try {

        const { email, password } = req.body;

        if (!email || !password) {

            return res.status(400).json({
                message: "Email and password are required"
            });

        }

        const user = await User.findOne({ email });

        if (!user) {

            return res.status(401).json({
                message: "Invalid email or password"
            });

        }

        if (user.accountLocked) {

            return res.status(403).json({
                message: "Account is locked. Contact administrator."
            });

        }

        const isMatch = await bcrypt.compare(
            password,
            user.password
        );

        if (!isMatch) {

            user.failedAttempts += 1;
            user.accountStatus = "Failed Attempt";

            if (user.failedAttempts >= 5) {

                user.accountLocked = true;
                user.accountStatus = "Account Locked";

                user.loginHistory.push({
                    status: "Account Locked"
                });

                await user.save();

                return res.status(403).json({
                    message: "Account locked after 5 failed attempts"
                });

            }

            user.loginHistory.push({
                status: "Failed Attempt"
            });

            await user.save();

            return res.status(401).json({

                message: "Invalid email or password",

                remainingAttempts: 5 - user.failedAttempts

            });

        }

        user.failedAttempts = 0;
        user.accountStatus = "Authenticated";

        user.loginHistory.push({
            status: "Successful Login"
        });

        await user.save();

        res.status(200).json({

            message: "Login successful",

            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                accountStatus: user.accountStatus,
                failedAttempts: user.failedAttempts,
                accountLocked: user.accountLocked,
                loginHistory: user.loginHistory
            }

        });

    } catch (error) {

        res.status(500).json({
            message: "Login failed",
            error: error.message
        });

    }

});


// FORGOT PASSWORD - SEND OTP

router.post("/forgot-password", async (req, res) => {

    try {

        const { email } = req.body;

        if (!email) {

            return res.status(400).json({
                message: "Email is required"
            });

        }

        const user = await User.findOne({ email });

        if (!user) {

            return res.status(200).json({
                message: "If the email is registered, an OTP will be sent."
            });

        }

        // Generate 6-digit OTP
        const otp = crypto.randomInt(100000, 1000000).toString();

        // Hash OTP
        const hashedOTP = await bcrypt.hash(otp, 10);

        user.resetOtpHash = hashedOTP;

        // OTP expires after 5 minutes
        user.resetOtpExpires = new Date(Date.now() + 5 * 60 * 1000);

        user.resetOtpAttempts = 0;

        // Clear old reset token
        user.resetTokenHash = null;
        user.resetTokenExpires = null;

        await user.save();

        try {

            await sendOTPEmail(email, otp);

        } catch (emailError) {

            user.resetOtpHash = null;
            user.resetOtpExpires = null;
            user.resetOtpAttempts = 0;

            await user.save();

            throw emailError;

        }

        res.status(200).json({

            message: "If the email is registered, an OTP will be sent."

        });

    } catch (error) {

        console.log("OTP Email Error:", error.message);

        res.status(500).json({
            message: "Unable to send OTP. Please try again."
        });

    }

});


// VERIFY OTP

router.post("/verify-otp", async (req, res) => {

    try {

        const { email, otp } = req.body;

        if (!email || !otp) {

            return res.status(400).json({
                message: "Email and OTP are required"
            });

        }

        if (!/^\d{6}$/.test(String(otp))) {

            return res.status(400).json({
                message: "Enter a valid 6-digit OTP"
            });

        }

        const user = await User.findOne({ email });

        if (!user || !user.resetOtpHash) {

            return res.status(400).json({
                message: "Invalid or expired OTP"
            });

        }

        // Check OTP expiry
        if (
            !user.resetOtpExpires ||
            user.resetOtpExpires < new Date()
        ) {

            user.resetOtpHash = null;
            user.resetOtpExpires = null;
            user.resetOtpAttempts = 0;

            await user.save();

            return res.status(400).json({
                message: "OTP expired. Request a new OTP."
            });

        }

        // Maximum 5 attempts
        if (user.resetOtpAttempts >= 5) {

            user.resetOtpHash = null;
            user.resetOtpExpires = null;
            user.resetOtpAttempts = 0;

            await user.save();

            return res.status(429).json({
                message: "Too many incorrect attempts. Request a new OTP."
            });

        }

        const isValidOTP = await bcrypt.compare(
            String(otp),
            user.resetOtpHash
        );

        if (!isValidOTP) {

            user.resetOtpAttempts += 1;

            await user.save();

            return res.status(400).json({

                message: "Incorrect OTP",

                remainingAttempts: 5 - user.resetOtpAttempts

            });

        }

        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString("hex");

        const hashedToken = crypto
            .createHash("sha256")
            .update(resetToken)
            .digest("hex");

        user.resetTokenHash = hashedToken;

        // Reset token expires after 15 minutes
        user.resetTokenExpires = new Date(Date.now() + 15 * 60 * 1000);

        // Clear OTP after successful verification
        user.resetOtpHash = null;
        user.resetOtpExpires = null;
        user.resetOtpAttempts = 0;

        await user.save();

        res.status(200).json({

            message: "OTP verified successfully",

            resetToken

        });

    } catch (error) {

        res.status(500).json({
            message: "OTP verification failed"
        });

    }

});


// RESET PASSWORD

router.post("/reset-password", async (req, res) => {

    try {

        const {
            email,
            resetToken,
            newPassword,
            confirmPassword
        } = req.body;

        if (!email || !resetToken || !newPassword || !confirmPassword) {

            return res.status(400).json({
                message: "All fields are required"
            });

        }

        // DFA validation
        if (!validatePasswordDFA(newPassword)) {

            return res.status(400).json({
                message: "Password does not satisfy the policy"
            });

        }

        if (newPassword !== confirmPassword) {

            return res.status(400).json({
                message: "Passwords do not match"
            });

        }

        const user = await User.findOne({ email });

        if (!user || !user.resetTokenHash) {

            return res.status(400).json({
                message: "Invalid or expired reset session"
            });

        }

        // Check reset token expiry
        if (
            !user.resetTokenExpires ||
            user.resetTokenExpires < new Date()
        ) {

            user.resetTokenHash = null;
            user.resetTokenExpires = null;

            await user.save();

            return res.status(400).json({
                message: "Reset session expired. Start again."
            });

        }

        // Hash received token
        const hashedToken = crypto
            .createHash("sha256")
            .update(resetToken)
            .digest("hex");

        const tokenBuffer = Buffer.from(hashedToken, "hex");
        const storedTokenBuffer = Buffer.from(user.resetTokenHash, "hex");

        if (
            tokenBuffer.length !== storedTokenBuffer.length ||
            !crypto.timingSafeEqual(tokenBuffer, storedTokenBuffer)
        ) {

            return res.status(401).json({
                message: "Invalid reset token"
            });

        }

        // Hash new password
        user.password = await bcrypt.hash(newPassword, 10);

        user.failedAttempts = 0;

        // Do not automatically unlock locked accounts
        if (!user.accountLocked) {
            user.accountStatus = "Registered";
        }

        user.loginHistory.push({
            status: "Password Reset"
        });

        // Clear reset token after use
        user.resetTokenHash = null;
        user.resetTokenExpires = null;

        await user.save();

        res.status(200).json({

            message: user.accountLocked
                ? "Password reset successful. Your account is still locked. Contact administrator."
                : "Password reset successful. You can now login with your new password."

        });

    } catch (error) {

        res.status(500).json({
            message: "Password reset failed"
        });

    }

});


// ADMIN ACCOUNT UNLOCK

router.put("/unlock", async (req, res) => {

    try {

        const adminKey = req.headers["admin-key"];
        const { email } = req.body;

        if (adminKey !== process.env.ADMIN_KEY) {

            return res.status(401).json({
                message: "Unauthorized admin access"
            });

        }

        const user = await User.findOne({ email });

        if (!user) {

            return res.status(404).json({
                message: "User not found"
            });

        }

        user.failedAttempts = 0;
        user.accountLocked = false;
        user.accountStatus = "Unlocked";

        user.loginHistory.push({
            status: "Account Unlocked"
        });

        await user.save();

        res.status(200).json({

            message: "Account unlocked successfully",

            user: {
                id: user._id,
                username: user.username,
                email: user.email,
                accountStatus: user.accountStatus,
                failedAttempts: user.failedAttempts,
                accountLocked: user.accountLocked
            }

        });

    } catch (error) {

        res.status(500).json({
            message: "Account unlock failed",
            error: error.message
        });

    }

});


// ADMIN VIEW ALL USERS

router.get("/users", async (req, res) => {

    try {

        const adminKey = req.headers["admin-key"];

        if (adminKey !== process.env.ADMIN_KEY) {

            return res.status(401).json({
                message: "Unauthorized admin access"
            });

        }

        const users = await User.find().select(
            "-password -resetOtpHash -resetTokenHash"
        );

        res.status(200).json({

            message: "Users fetched successfully",
            users

        });

    } catch (error) {

        res.status(500).json({
            message: "Failed to fetch users",
            error: error.message
        });

    }

});


module.exports = router;
