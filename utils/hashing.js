import { hash,compare} from "bcryptjs";
import {createHmac} from 'crypto'

export const doHash = (value,saltValue)=>{
    const result = hash(value,saltValue);
    return result;
}

export const compareHash = (value,hashedValue)=>{
    const result = compare(value,hashedValue);
    return result;
}

export const hmacProcess = (value,key)=>{
    const result = createHmac('sha256',key).update(value).digest('hex')
    return result
}

