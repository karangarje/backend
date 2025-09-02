const jwt = require("jsonwebtoken")


exports.auth = async (req, res, next) => {
  try {
    // safe access using optional chaining
    const headerAuth =
      req.header?.("Authorization") ||
      req.get?.("Authorization") ||
      req.headers?.authorization;

    // Use optional chaining to avoid crashes if cookies/body are undefined
    let token = req.cookies?.token || req.body?.token || headerAuth;

    // If header contains "Bearer <token>", extract the token part
    if (typeof token === "string" && token.trim().startsWith("Bearer ")) {
      token = token.trim().split(" ")[1];
    }

    console.log("[AUTH] token present?:", !!token);

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Token is missing",
      });
    }

    if (!process.env.JWT_SECRET) {
      console.error("[AUTH] JWT_SECRET is not defined on server!");
      return res.status(500).json({
        success: false,
        message: "Server misconfiguration",
      });
    }

    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      req.user = payload;
      return next();
    } catch (verifyErr) {
      console.error("[AUTH] jwt.verify error:", verifyErr.name, verifyErr.message);
      return res.status(401).json({
        success: false,
        message: "Invalid token",
      });
    }
  } catch (err) {
    console.error("[AUTH] unexpected error:", err);
    return res.status(500).json({
      success: false,
      message: "Error in validating token",
    });
  }
};

exports.isStudent = async(req,res,next) => {
    try{
        if(req.user.accountType !== "Student") {
            return res.status(401).json({
                success:false,
                message:'This is a protected route for Students only',
            });
        }
        next();
    }
    catch(error) {
        return res.status(500).json({
            success:false,
            message:'User role cannot be verified, please try again'
        })
    }
}
exports.isInstructor = async(req,res,next) => {
    try{
        if(req.user.accountType !== "Instructor") {
            return res.status(401).json({
                success:false,
                message:'This is a protected route for Instructor only',
            });
        }
        next();
    }
    catch(error) {
        return res.status(500).json({
            success:false,
            message:'User role cannot be verified, please try again'
        })
    }
}

exports.isAdmin = async (req, res, next) => {
    try{
           if(req.user.accountType !== "Admin") {
               return res.status(401).json({
                   success:false,
                   message:'This is a protected route for Admin only',
               });
           }
           next();
    }
    catch(error) {
       return res.status(500).json({
           success:false,
           message:'User role cannot be verified, please try again'
       })
    }
   }
