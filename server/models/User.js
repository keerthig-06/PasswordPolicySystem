
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
        enum: ["Registered", "Password Validation", "Authenticated", "Failed Attempt", "Account Locked", "Unlocked"],
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
    ]
});

module.exports = mongoose.model("User", UserSchema);
