import mongoose from "mongoose";

const collection = "users";

const userSchema = new mongoose.Schema(
  {
    first_name: { type: String, required: true },
    last_name:  { type: String, required: true },
    email:      { type: String, required: true, unique: true, index: true },
    age:        { type: Number, required: true },
    password:   { type: String, required: true },
    cart:       { type: mongoose.Schema.Types.ObjectId, ref: "carts" },
    role:       { type: String, enum: ["user", "admin"], default: "user" }
  },
  { timestamps: true }
);

const UserModel = mongoose.model(collection, userSchema);
export default UserModel;
