import { Router } from "express";
import jwt from "jsonwebtoken";
import passport from "passport";
import UserModel from "../models/user.model.js";
import { createHash, isValidPassword } from "../utils/hash.js";

const router = Router();

const COOKIE_NAME = process.env.COOKIE_NAME || "coderCookieToken";
const JWT_SECRET  = process.env.JWT_SECRET  || "dev_secret";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "1h";

// REGISTER
router.post("/register", async (req, res) => {
  try {
    const { first_name, last_name, email, age, password, cart, role } = req.body;
    if (!first_name || !last_name || !email || !age || !password) {
      return res.status(400).send({ status: "error", message: "Faltan campos obligatorios" });
    }
    const exist = await UserModel.findOne({ email });
    if (exist) return res.status(400).send({ status: "error", message: "El email ya está registrado" });

    const user = await UserModel.create({
      first_name,
      last_name,
      email,
      age,
      password: createHash(password),
      cart: cart || null,
      role: role || "user",
    });

    res.send({ status: "success", payload: { _id: user._id, email: user.email } });
  } catch (err) {
    res.status(500).send({ status: "error", message: err.message });
  }
});

// LOGIN
router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).send({ status: "error", message: "Email y password son requeridos" });

    const user = await UserModel.findOne({ email }).populate("cart");
    if (!user) return res.status(401).send({ status: "error", message: "Credenciales inválidas" });

    if (!isValidPassword(password, user.password))
      return res.status(401).send({ status: "error", message: "Credenciales inválidas" });

    const token = jwt.sign(
      {
        user: {
          _id: user._id,
          first_name: user.first_name,
          last_name: user.last_name,
          email: user.email,
          age: user.age,
          role: user.role,
          cart: user.cart?._id || null,
        },
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res
      .cookie(COOKIE_NAME, token, {
        httpOnly: true,
        maxAge: 60 * 60 * 1000,
      })
      .send({ status: "success", message: "Login OK" });
  } catch (err) {
    res.status(500).send({ status: "error", message: err.message });
  }
});

// CURRENT
router.get(
  "/current",
  passport.authenticate("jwt", { session: false }),
  (req, res) => {
    const u = req.user;
    res.send({
      status: "success",
      payload: {
        _id: u._id,
        first_name: u.first_name,
        last_name: u.last_name,
        email: u.email,
        age: u.age,
        role: u.role,
        cart: u.cart?._id || null,
      },
    });
  }
);

// LOGOUT
router.post("/logout", (req, res) => {
  res.clearCookie(COOKIE_NAME).send({ status: "success", message: "Logout OK" });
});

export default router;
