import mongoose from "mongoose";
import { config } from "./config.js";

async function connectDB(){
    try{
        await mongoose.connect(config.MONGO_URI);
        console.log("Database connected successfully");
    }catch(error){
        console.log(error);
    }
}

export default connectDB;