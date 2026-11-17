
const express = require("express");
const bcrypt = require("bcryptjs");
const User = require("../models/User");

const router = express.Router();


// DFA PASSWORD VALIDATION

function validatePasswordDFA(password) {

    if (typeof password !== "string") {
        return false;
    }

    // State stores password length and character conditions
    let state = 0;

    const specialCharacters = '!@#$%^&*(),.?":{}|<>';

    for (let i = 0; i < password.length; i++) {

        const ch = password[i];

        // Reject line breaks
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

        // Uppercase letter
        if (ch >= "A" && ch <= "Z") {
            mask |= 1;
        }

        // Lowercase letter
        if (ch >= "a" && ch <= "z") {
            mask |= 2;
        }

        // Number
        if (ch >= "0" && ch <= "9") {
            mask |= 4;
        }

        // Special character
        if (specialCharacters.includes(ch)) {
            mask |= 8;
        }

        // Update password length
        length = Math.min(length + 1, 8);

        // Move to next DFA state
        state = length * 16 + mask;
    }

    // Accepting state
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

        // DFA Password Validation
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

        // Hash password
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

        // Check account lock
        if (user.accountLocked) {

            return res.status(403).json({
                message: "Account is locked. Contact administrator."
            });

        }

        // Compare password
        const isMatch = await bcrypt.compare(
            password,
            user.password
        );

        // Failed login
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

        // Successful login
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

        const users = await User.find().select("-password");

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
