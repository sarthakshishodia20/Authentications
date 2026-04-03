import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { config } from "../config/config.js";

async function register(req, res) {
    const { username, email, password } = req.body;
    const isAlreadyRegistered = await userModel.findOne(
        { $or: [{ username }, { email }] }
    );
    if (isAlreadyRegistered) {
        return res.status(409).json({ message: "User already registered! Please use different username/email" });
    }
    const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");
    const user = await userModel.create({
        username,
        email,
        password: hashedPassword
    });
    const token = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "9d" });
    return res.status(201).json({ message: "User registered successfully", user: { username, email }, token });
}

async function getMe(req, res) {
    const incomingToken = req.headers.authorization?.split(" ")[1];
    if (!incomingToken) {
        return res.status(401).json({ message: "Unauthorized" });
    }
    let decodedToken;
    try {
        decodedToken = jwt.verify(incomingToken, config.JWT_SECRET);
    } catch (error) {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
    const user = await userModel.findById(decodedToken.id);
    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }
    return res.status(200).json({ user: { username: user.username, email: user.email, createdAt: user.createdAt }, message: "User found" });
}

export { register, getMe };