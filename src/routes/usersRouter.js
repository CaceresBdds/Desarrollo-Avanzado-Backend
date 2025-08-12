import { Router } from "express";
import passport from "passport";
import UserModel from "../models/user.model.js";
import { createHash } from "../utils/hash.js";
import { authorization } from "../middlewares/authorization.js";

const router = Router();

router.get(
  "/",
  passport.authenticate("jwt", { session: false }),
  authorization(["admin"]),
  async (req, res) => {
    const users = await UserModel.find().select("-password");
    res.send({ status: "success", payload: users });
  }
);

router.get(
  "/:id",
  passport.authenticate("jwt", { session: false }),
  authorization(["admin"]),
  async (req, res) => {
    const user = await UserModel.findById(req.params.id).select("-password");
    if (!user) return res.status(404).send({ status: "error", message: "Usuario no encontrado" });
    res.send({ status: "success", payload: user });
  }
);

router.post(
  "/",
  passport.authenticate("jwt", { session: false }),
  authorization(["admin"]),
  async (req, res) => {
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
    res.status(201).send({ status: "success", payload: { _id: user._id, email: user.email } });
  }
);


router.put(
  "/:id",
  passport.authenticate("jwt", { session: false }),
  async (req, res) => {
    const { id } = req.params;
    if (req.user.role !== "admin" && req.user._id.toString() !== id) {
      return res.status(403).send({ status: "error", message: "No autorizado" });
    }

    const update = { ...req.body };
    if (update.password) {
      update.password = createHash(update.password);
    }

    if (update.email) {
      const exist = await UserModel.findOne({ email: update.email, _id: { $ne: id } });
      if (exist) return res.status(400).send({ status: "error", message: "Email ya en uso" });
    }

    const user = await UserModel.findByIdAndUpdate(id, update, { new: true }).select("-password");
    if (!user) return res.status(404).send({ status: "error", message: "Usuario no encontrado" });

    res.send({ status: "success", payload: user });
  }
);

router.delete(
  "/:id",
  passport.authenticate("jwt", { session: false }),
  authorization(["admin"]),
  async (req, res) => {
    const del = await UserModel.findByIdAndDelete(req.params.id);
    if (!del) return res.status(404).send({ status: "error", message: "Usuario no encontrado" });
    res.send({ status: "success", message: "Usuario eliminado" });
  }
);

export default router;
