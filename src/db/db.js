import mongoose from 'mongoose';
import { DB_NAME } from '../constants/constant.js';

const ConnectDb= async ()=>{
    try {
        const connectionInstance=await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`);
        console.log(`Database connected successfully: ${connectionInstance.connection.host}`);


        
    } catch (error) {
        console.error("Error while connecting to database",error.message);
        process.exit(1);
    }
}

export {ConnectDb}