import mongoose from "mongoose";

export const connectDB=async ()=>{
    const MONGODB_URI="mongodb://localhost:27017/AUTHENTICATION"
    await mongoose.connect(MONGODB_URI).then(()=>{
        console.log("DB Connected")
    })
}

