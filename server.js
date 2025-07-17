import express from 'express'
import helmet from 'helmet'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import { connectDB } from './db.js'
import { authRouter } from './routers/authRouter.js'


const app=express();
const PORT=5500


await connectDB()

app.use(express.json())
app.use(cors())
app.use(helmet())
app.use(cookieParser())

app.get('/',(req,res)=>{
    res.send("Welcome To Authentication")
})

app.use('/api/auth',authRouter);

app.listen(PORT,()=>{
    console.log("Server Running on 5500")
})