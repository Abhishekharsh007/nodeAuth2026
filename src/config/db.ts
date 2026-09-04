import mongoose from "mongoose";

export async function connectDB() { 
    try {
        await mongoose.connect(process.env.MONGO_URL!);
        console.log("Mongo DB connection is successful!");
    } catch (err) {
        console.error("Mongo DB connection error!", err);
        process.exit(1);
    }
}
