import mongoose from "mongoose";

const sessionSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "users",
        required: true,
    },
    refreshTokenHashed: {
        type: String,
        required: true,
    },
    ip:{
        type: String,
        required: true,
    },
    userAgent:{
        type: String,
        required: true,
    },
    revoked:{
        type: Boolean,
        default: false,
    },
}, { timestamps: true });
    
const sessionModel = mongoose.model("sessions", sessionSchema);
export default sessionModel;