import mongoose, { mongo } from "mongoose";

const postSchema = new mongoose.Schema({
    title:{
        type:String,
        required:true,
        trim:true
    },
    description:{
        type:String,
        required:true,
        trim:true
    },
    userId:{
        type:mongoose.Schema.Types.ObjectId,
        ref:'users',
        required:true
    },

},{timestamps:true});

export const postModel = mongoose.model("posts",postSchema)