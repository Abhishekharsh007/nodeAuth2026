import { connectDB } from "./config/db";
import dotenv from "dotenv";
import http from "http";
import app from "./app";

dotenv.config();

async function startServer() { 
    await connectDB();

    const server = http.createServer(app);

    server.listen(process.env.PORT, () => { 
        console.log(`Server is running!`);
    });
}

startServer().catch(err => { 
    console.error('Error while starting the server', err);
    process.exit(1);
})
