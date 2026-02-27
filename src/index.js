import { ConnectDb } from "./db/db.js";
import dotenv from 'dotenv';
import app from './app.js';

dotenv.config({
    path:"./.env"
})

const Port=process.env.PORT || 20000
ConnectDb()
.then(()=>{
    app.listen(Port,()=>{
        console.log(`Server is running at port ${Port}`);
    })
})
.catch((err)=>{
    console.log("Mongo db connection failed !!! ",err);
})
