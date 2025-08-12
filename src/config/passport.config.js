import passport from "passport";
import jwt from "passport-jwt";
import UserModel from "../models/user.model.js";

const JWTStrategy = jwt.Strategy;
const ExtractJwt = jwt.ExtractJwt;

const cookieExtractor = (req) => {
  if (req && req.cookies) {
    return req.cookies[process.env.COOKIE_NAME || "coderCookieToken"] || null;
  }
  return null;
};

export const initializePassport = () => {
  passport.use(
    "jwt",
    new JWTStrategy(
      {
        jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor]),
        secretOrKey: process.env.JWT_SECRET || "dev_secret",
      },
      async (jwtPayload, done) => {
        try {
          const user = await UserModel.findById(jwtPayload.user._id).populate("cart");
          if (!user) return done(null, false, { message: "Usuario no encontrado" });
          return done(null, user);
        } catch (err) {
          return done(err);
        }
      }
    )
  );
};
