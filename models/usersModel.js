import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
    email:{
        type:String,
        required:true,
        trim:true,
        unique:true,
        minLength:5,
        lowercase:true
    },
    
    password:{
        type:String,
        required:true,
        trim:true,
        unique:true,
        select:false
    },
    verified:{
        type:Boolean,
        default:false
    },
    verificationCode:{
        type:String,
        select:false
    },
    verificationCodeValidation:{
        type:Number,
        default:false
    },
    forgotPasswordCode:{
        type:String,
        select:false,
    },
    forgotPasswordCodeValidation:{
        type:String,
        select:false,
    }
},{timestamps:true});

export const userModel = mongoose.model("users",userSchema)