// userController.js

import { User } from "../models/userSchema.js";
import ErrorHandler from "../middlewares/error.js";
import { sendToken } from "../utils/jwtToken.js";
import { validationResult } from "express-validator";

// Register a new user
export const register = async (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return next(new ErrorHandler("Validation error", 400, errors.array()));
  }

  const { name, email, phone, password, role } = req.body;

  try {
    let user = await User.findOne({ email });

    if (user) {
      return next(new ErrorHandler("Email already registered!", 400));
    }

    user = new User({
      name,
      email,
      phone,
      password,
      role,
    });

    await user.save();

    sendToken(user, 201, res, "User Registered!");
  } catch (error) {
    next(error);
  }
};

// User login
export const login = async (req, res, next) => {
  const { email, password, role } = req.body;

  try {
    let user = await User.findOne({ email }).select("+password");

    if (!user) {
      return next(new ErrorHandler("Invalid Email Or Password.", 400));
    }

    const isPasswordMatched = await user.comparePassword(password);

    if (!isPasswordMatched) {
      return next(new ErrorHandler("Invalid Email Or Password.", 400));
    }

    if (user.role !== role) {
      return next(
        new ErrorHandler(`User with provided email and ${role} not found!`, 404)
      );
    }

    sendToken(user, 200, res, "User Logged In!");
  } catch (error) {
    next(error);
  }
};

// Logout user
export const logout = async (req, res, next) => {
  try {
    res.clearCookie("token").json({
      success: true,
      message: "Logged Out Successfully.",
    });
  } catch (error) {
    next(error);
  }
};

// Get user profile
export const getUser = async (req, res, next) => {
  try {
    const user = await User.findById(req.user._id);

    if (!user) {
      return next(new ErrorHandler("User not found", 404));
    }

    res.status(200).json({
      success: true,
      user,
    });
  } catch (error) {
    next(error);
  }
};
