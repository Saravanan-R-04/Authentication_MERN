import Joi from "joi";

export const signupSchema = Joi.object({
    email:Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({
            tlds:{allow:['com','net']}
        }),
    password:Joi.string()
        .required()
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$')),
    
})
export const acceptCodeSchema = Joi.object({
    email:Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({
            tlds:{allow:['com','net']}
        }),
    providedCode:Joi.number()               
        .required()
    
})
export const changePasswordSchema=Joi.object({
    newPassword:Joi.string()
        .required()
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$')),
    oldPassword:Joi.string()
        .required()
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$')),
    
})
export const acceptFPCodeSchema = Joi.object({
    email:Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({
            tlds:{allow:['com','net']}
        }),
    providedCode:Joi.number()
        .required(),
    newPassword:Joi.string()
        .required()
        .pattern(new RegExp('^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d).{8,}$'))
})