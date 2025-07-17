import { acceptFPCodeSchema, changePasswordSchema, signupSchema } from "../middlewares/validator.js";
import { userModel } from "../models/usersModel.js";
import {compareHash, doHash, hmacProcess} from '../utils/hashing.js'
import jwt from "jsonwebtoken";
import { transport } from "../middlewares/sendMail.js";
import { acceptCodeSchema } from "../middlewares/validator.js";
export const signup = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Validate input
    const { error } = signupSchema.validate({ email, password });
    if (error) {
      return res.status(401).json({
        success: false,
        message: error.details[0].message
      });
    }

    // Check if user exists
    const existUser = await userModel.findOne({ email });
    if (existUser) {
      return res.status(401).json({
        success: false,
        message: "User Already Exists"
      });
    }

    // Hash password and create user
    const hashedPassword = await doHash(password, 12);
    const newUser = new userModel({
      email,
      password: hashedPassword
    });

    await newUser.save();

    return res.status(201).json({
      success: true,
      message: "User Created Successfully"
    });
  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Server Error"
    });
  }
};

export const signin = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Validate input
    const { error } = signupSchema.validate({ email, password });
    if (error) {
      return res.status(401).json({
        success: false,
        message: error.details[0].message
      });
    }

    // Check if user exists
    const existUser = await userModel.findOne({ email }).select('+password');
    if (!existUser) {
      return res.status(401).json({
        success: false,
        message: "You need to Sign Up"
      });
    }

    // Compare password
    const isMatch = await compareHash(password, existUser.password);
    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Invalid Email or Password"
      });
    }

    // Generate token
    const token = jwt.sign(
      {
        userId: existUser._id,
        email: existUser.email,
        verified: existUser.verified
      },
      "test-secret",
      { expiresIn: "8h" }
    );

    // Set secure cookie
    res.cookie('Authorization', 'Bearer ' + token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      expires: new Date(Date.now() + 8 * 60 * 60 * 1000), // 8 hours
      sameSite: 'strict'
    });

    return res.status(200).json({
      success: true,
      message: "Logged In Successfully",
      token
    });

  } catch (error) {
    console.log(error);
    return res.status(500).json({
      success: false,
      message: "Server Error"
    });
  }
};
export const signout=async(req,res)=>{
    res.clearCookie('Authorisation').status(200).json({success:true,message:"Sign Out Successfully"})
}
export const sendVerificationCode = async(req,res)=>{
    const {email}=req.body;
    try{
        const existingUser = await userModel.findOne({email})

        if(!existingUser){
            return res  
                    .status(401)
                    .json({success:false,message:"User does not exists"});
        }
        if(existingUser.verified)
        {
            return res  
                    .status(401)
                    .json({success:false,message:"You are already verified"});
        }
        const codeValue = Math.floor(Math.random()*1000000).toString();
        let info = await transport.sendMail({
            from:process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
            to:existingUser.email,
            subject:"Verification Code",
            html:'<h1>'+codeValue+'</h1>'
        })
        if(info.accepted[0]===existingUser.email)
        {
            const hashedCodeValue=hmacProcess(codeValue,process.env.HMAC_VERIFICATION_CODE_SECRET)  
            existingUser.verificationCode=hashedCodeValue;
            existingUser.verificationCodeValidation=Date.now();
            await existingUser.save();
            return res.status(200).json({success:true,message:"Code Sent"})        
        }
    }   
    catch(error)
    {
        console.log(error);
    }
}
export const verifyVerificationcode = async (req, res) => {
  const { email, providedCode } = req.body;

  try {
    // Validate the input
    const { error } = acceptCodeSchema.validate({ email, providedCode });
    if (error) {
      return res.status(401).json({
        success: false,
        message: error.details[0].message
      });
    }

    // Convert the provided code to string
    const codeValue = providedCode.toString();

    // Fetch the user with necessary fields
    const existingUser = await userModel.findOne({ email }).select("+verificationCode +verificationCodeValidation");

    if (!existingUser) {
      return res.status(401).json({
        success: false,
        message: "User does not exist"
      });
    }

    // Check if user is already verified
    if (existingUser.verified) {
      return res.status(400).json({
        success: false,
        message: "User is already verified"
      });
    }

    // Check if code and validation time are present
    if (!existingUser.verificationCode || !existingUser.verificationCodeValidation) {
      return res.status(400).json({
        success: false,
        message: "Something is wrong with the verification code"
      });
    }

    // Check if the code has expired (after 5 minutes)
    if (Date.now() - existingUser.verificationCodeValidation > 5 * 60 * 1000) {
      return res.status(400).json({
        success: false,
        message: "Code has expired"
      });
    }

    // Hash the provided code
    const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);

    // Compare hashed values
    if (hashedCodeValue === existingUser.verificationCode) {
      existingUser.verified = true;
      existingUser.verificationCode = undefined;
      existingUser.verificationCodeValidation = undefined;
      await existingUser.save();

      return res.status(200).json({
        success: true,
        message: "Your account has been verified"
      });
    }

    // Wrong code
    return res.status(400).json({
      success: false,
      message: "Incorrect verification code"
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Server Error: " + error.message
    });
  }
};
export const changePassword=async(req,res)=>{
  
  const {email,oldPassword,newPassword}=req.body;
  try{
    const {error}=changePasswordSchema.validate({newPassword,oldPassword})  
    if(error)
    {
      return res.status(401).json({
        success:false,
        message:error.details[0].message
      });
    }
    const existingUser = await userModel.findOne({email}).select('+password')
    if(!existingUser)
    {
      return res.status(401).json({
        success:false,
        message:"User Not found"
      })
    }
    const result=await compareHash(oldPassword,existingUser.password)
    if(!result)
    {
      return res.status(401).json({
        success:false,
        message:'Invalid Credentials'
      })
    }
    const hashedPassword = await doHash(newPassword,12);
    existingUser.password = hashedPassword;
    await existingUser.save();
    return res.status(200).json({
      success:true,
      message:'Password Updated'
    })
  }
  catch(error)
  {
    console.log(error);
  }
}
export const sendForgotPasswordCode = async(req,res)=>{
    const {email}=req.body;
    try{
        const existingUser = await userModel.findOne({email})

        if(!existingUser){
            return res  
                    .status(401)
                    .json({success:false,message:"User does not exists"});
        }
        
        const codeValue = Math.floor(Math.random()*1000000).toString();
        let info = await transport.sendMail({
            from:process.env.NODE_CODE_SENDING_EMAIL_ADDRESS,
            to:existingUser.email,
            subject:"Forgot Password Code",
            html:'<h1>'+codeValue+'</h1>'
        })
        if(info.accepted[0]===existingUser.email)
        {
            const hashedCodeValue=hmacProcess(codeValue,process.env.HMAC_VERIFICATION_CODE_SECRET)  
            existingUser.forgotPasswordCode=hashedCodeValue;
            existingUser.forgotPasswordCodeValidation=Date.now();
            await existingUser.save();
            return res.status(200).json({success:true,message:"Code Sent"})        
        }
    }   
    catch(error)
    {
        console.log(error);
    }
}
export const verifyForgotPasswordCode = async (req, res) => {
  const { email, providedCode,newPassword} = req.body;

  try {
    // Validate the input
    const { error } = acceptFPCodeSchema.validate({ email, providedCode,newPassword});
    if (error) {
      return res.status(401).json({
        success: false,
        message: error.details[0].message
      });
    }

    // Convert the provided code to string
    const codeValue = providedCode.toString();

    // Fetch the user with necessary fields
    const existingUser = await userModel.findOne({ email }).select("+forgotPasswordCode +forgotPasswordCodeValidation");

    if (!existingUser) {
      return res.status(401).json({
        success: false,
        message: "User does not exist"
      });
    }

    

    // Check if code and validation time are present
    if (!existingUser.forgotPasswordCode || !existingUser.forgotPasswordCodeValidation) {
      return res.status(400).json({
        success: false,
        message: "Something is wrong with the verification code"
      });
    }

    // Check if the code has expired (after 5 minutes)
    if (Date.now() - existingUser.forgotPasswordCodeValidation > 5 * 60 * 1000) {
      return res.status(400).json({
        success: false,
        message: "Code has expired"
      });
    }

    // Hash the provided code
    const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);

    // Compare hashed values
    if (hashedCodeValue === existingUser.forgotPasswordCode) {
      const hashedPassword = await doHash(newPassword, 12);
      existingUser.password=hashedPassword
      existingUser.forgotPasswordCode = undefined;
      existingUser.forgotPasswordCodeValidation= undefined;
      await existingUser.save();

      return res.status(200).json({
        success: true,
        message: "Password Updated Successfully"
      });
    }

    // Wrong code
    return res.status(400).json({
      success: false,
      message: "Incorrect verification code"
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Server Error: " + error.message
    });
  }
};
