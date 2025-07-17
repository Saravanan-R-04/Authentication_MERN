import express from 'express'
import {signup,signin,signout,sendVerificationCode,verifyVerificationcode, changePassword, sendForgotPasswordCode, verifyForgotPasswordCode} from '../controllers/authController.js'
// import { identifier } from '../middlewares/identification.js'
export const authRouter = express.Router()

authRouter.post('/signup',signup)
authRouter.post('/signin',signin)
authRouter.post('/signout',signout)
authRouter.patch('/send-verification-code',sendVerificationCode)
authRouter.patch('/verify-verification-code',verifyVerificationcode)
authRouter.post('/change-password',changePassword)
authRouter.patch('/send-forgot-password-code',sendForgotPasswordCode)
authRouter.patch('/verify-forgot-password-code',verifyForgotPasswordCode)