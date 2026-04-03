import userModel from "../models/user.model.js";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import { config } from "../config/config.js";
import sessionModel from "../models/session.model.js";

async function login(req, res) {
    try {
        const { username, email, password } = req.body;
        const user = await userModel.findOne({ $or: [{ username }, { email }] });
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }
        const hashedPassword = crypto.createHash("sha256").update(password).digest("hex");
        if (user.password !== hashedPassword) {
            return res.status(401).json({ message: "Invalid credentials" });
        }
        const accesstoken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "15m" });
        const refreshtoken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "7d" });
        const hashedRefreshToken = crypto.createHash("sha256").update(refreshtoken).digest("hex");
        await sessionModel.create({
            userId: user._id,
            refreshTokenHashed: hashedRefreshToken,
            ip: req.ip,
            userAgent: req.headers["user-agent"],
        });
        res.cookie("refreshtoken", refreshtoken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        return res.status(200).json({ message: "Login successful", user: { username: user.username, email: user.email }, accesstoken });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error: error.message });
    }
}

async function register(req, res) {
    try {
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
        const accesstoken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "15m" });
        const refreshtoken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "7d" });
        const hashedRefreshToken = crypto.createHash("sha256").update(refreshtoken).digest("hex");
        await sessionModel.create({
            userId: user._id,
            refreshTokenHashed: hashedRefreshToken,
            ip: req.ip,
            userAgent: req.headers["user-agent"],
        });
        res.cookie("refreshtoken", refreshtoken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            maxAge: 7 * 24 * 60 * 60 * 1000,
        });
        return res.status(201).json({ message: "User registered successfully", user: { username, email }, accesstoken });
    } catch (error) {
        return res.status(500).json({ message: "Internal server error", error: error.message });
    }
}

async function getRefreshToken(req,res){
    const refreshToken = req.cookies.refreshtoken;
    if(!refreshToken){
        return res.status(401).json({ message: "Unauthorized" });
    }
    let decodedToken;
    try {
        decodedToken = jwt.verify(refreshToken, config.JWT_SECRET);
    } catch (error) {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
    const hashedRefreshToken = crypto.createHash("sha256").update(refreshToken).digest("hex");
    const session = await sessionModel.findOne({ refreshTokenHashed: hashedRefreshToken ,revoked:false});
    if(!session){
        return res.status(404).json({ message: "Session not found" });
    }
    const user = await userModel.findById(decodedToken.id);
    if(!user){
        return res.status(404).json({ message: "User not found" });
    }
    const newAccessToken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "15m" });
    const newRefreshToken = jwt.sign({ id: user._id }, config.JWT_SECRET, { expiresIn: "7d" });
    const newRefreshTokenHash = crypto.createHash("sha256").update(newRefreshToken).digest("hex");
    session.refreshTokenHashed = newRefreshTokenHash;
    await session.save();
    res.cookie("refreshtoken", newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    return res.status(200).json({ message: "Token refreshed successfully", accesstoken: newAccessToken });
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

async function logout(req,res){
    const refreshtoken = req.cookies.refreshtoken;
    if(!refreshtoken){
        return res.status(401).json({ message: "Unauthorized" });
    }
    const hashedRefreshToken = crypto.createHash("sha256").update(refreshtoken).digest("hex");
    const session = await sessionModel.findOne({ refreshTokenHashed: hashedRefreshToken ,revoked:false});
    if(!session){
        return res.status(404).json({ message: "Session not found" });
    }
    await sessionModel.updateOne({ refreshTokenHashed: hashedRefreshToken }, { revoked: true });
    res.clearCookie("refreshtoken");
    return res.status(200).json({ message: "Logout successful" });
}

async function logoutAll(req,res){
    const refreshtoken = req.cookies.refreshtoken;
    if(!refreshtoken){
        return res.status(401).json({ message: "Unauthorized" });
    }
    const hashedRefreshToken = crypto.createHash("sha256").update(refreshtoken).digest("hex");
    const session = await sessionModel.findOne({ refreshTokenHashed: hashedRefreshToken ,revoked:false});
    if(!session){
        return res.status(404).json({ message: "Session not found" });
    }
    await sessionModel.updateMany({ userId: session.userId }, { revoked: true });
    res.clearCookie("refreshtoken");
    return res.status(200).json({ message: "Logout successful" });
}

export { login, register, getMe, getRefreshToken, logout, logoutAll };