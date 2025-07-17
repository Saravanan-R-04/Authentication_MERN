// import jwt from 'jsonwebtoken';

// export const identifier = (req, res, next) => {
//   let token;

//   // Normalize header key to lower case
//   const clientType = req.headers['client']?.toLowerCase();

//   // 1. Get token from Authorization header if client is not-browser (e.g., Postman, mobile)
//   if (clientType === 'not-browser') {
//     const authHeader = req.headers['authorization']; // Always lowercase in Node.js
//     if (authHeader && authHeader.startsWith('Bearer ')) {
//       token = authHeader.split(' ')[1]; // Extract the token part
//     } else {
//       return res.status(403).json({
//         success: false,
//         message: 'Authorization header missing or improperly formatted'
//       });
//     }
//   }

//   // 2. Else, get token from cookie (browser)
//   else {
//     token = req.cookies['Authorisation'];
//   }

//   // Check if token exists
//   if (!token) {
//     return res.status(403).json({
//       success: false,
//       message: 'Unauthorized - No token found'
//     });
//   }

//   try {
//     // Verify token
//     const jwtVerified = jwt.verify(token,'test-secret');

//     // Optional: Ensure required fields are present
//     if (!jwtVerified.userId || jwtVerified.verified === undefined) {
//       return res.status(403).json({
//         success: false,
//         message: 'Invalid token payload'
//       });
//     }

//     // Attach decoded data to req
//     req.user = {
//       userId: jwtVerified.userId,
//       verified: jwtVerified.verified
//     };

//     next();
//   } catch (error) {
//     console.error('JWT Verification Error:', error.message);
//     return res.status(401).json({
//       success: false,
//       message: 'Invalid or expired token'
//     });
//   }
// };
