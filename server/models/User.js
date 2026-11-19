
const mongoose = require("mongoose");

const UserSchema = new mongoose.Schema({

    username: {
        type: String,
        required: true
    },

    email: {
        type: String,
        required: true,
        unique: true
    },

    password: {
        type: String,
        required: true
    },

    failedAttempts: {
        type: Number,
        default: 0
    },

    accountLocked: {
        type: Boolean,
        default: false
    },

    accountStatus: {
        type: String,
        enum: [
            "Registered",
            "Password Validation",
            "Authenticated",
            "Failed Attempt",
            "Account Locked",
            "Unlocked"
        ],
        default: "Registered"
    },

    loginHistory: [
        {
            status: String,
            date: {
                type: Date,
                default: Date.now
            }
        }
    ],

    // FORGOT PASSWORD - OTP DETAILS

    resetOtpHash: {
        type: String,
        default: null
    },

    resetOtpExpires: {
        type: Date,
        default: null
    },

    resetOtpAttempts: {
        type: Number,
        default: 0
    },

    // PASSWORD RESET TOKEN

    resetTokenHash: {
        type: String,
        default: null
    },

    resetTokenExpires: {
        type: Date,
        default: null
    }

});

module.exports = mongoose.model("User", UserSchema);
