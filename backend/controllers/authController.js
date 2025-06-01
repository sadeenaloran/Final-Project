import jwt from "jsonwebtoken";
import UserModel from "../models/userModel.js";
import {
  registerSchema,
  loginSchema,
  changePasswordSchema,
} from "../utils/validation.js";
import passport from "../config/passport.js";
import { generateToken, generateRefreshToken } from "../utils/jwt.js";
import { sanitizeUser, createResponse } from "../utils/helpers.js";

// Start Google OAuth flow
export const googleAuth = passport.authenticate("google", {
  scope: ["profile", "email"],
});

// Handle Google OAuth callback
export const googleCallback = (req, res, next) => {
  passport.authenticate(
    "google",
    { failureRedirect: "/login" },
    async (err, user) => {
      if (err) {
        console.error("Google OAuth error:", err);
        return res.redirect(
          `${process.env.CLIENT_URL}/login?error=oauth_error`
        );
      }

      if (!user) {
        return res.redirect(
          `${process.env.CLIENT_URL}/login?error=oauth_failed`
        );
      }

      try {
        // Log user in with session
        req.logIn(user, (err) => {
          if (err) {
            console.error("Login error:", err);
            return res.redirect(
              `${process.env.CLIENT_URL}/login?error=login_failed`
            );
          }

          // Generate JWT tokens
          const tokenPayload = { id: user.id, email: user.email };
          const accessToken = generateToken(tokenPayload);
          const refreshToken = generateRefreshToken(tokenPayload);

          // Set HTTP-only cookies for security
          res.cookie("accessToken", accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
          });

          res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
          });

          // Redirect to client with success
          return res.redirect(
            `${process.env.CLIENT_URL}/dashboard?login=success`
          );
        });
      } catch (error) {
        console.error("Callback processing error:", error);
        return res.redirect(
          `${process.env.CLIENT_URL}/login?error=processing_error`
        );
      }
    }
  )(req, res, next);
};

// Get current user
export const getCurrentUser = (req, res) => {
  try {
    if (!req.user) {
      return res
        .status(401)
        .json(
          createResponse(
            false,
            "Not authenticated",
            null,
            "User not found in session"
          )
        );
    }

    const sanitizedUser = sanitizeUser(req.user);
    return res.json(
      createResponse(true, "User retrieved successfully", sanitizedUser)
    );
  } catch (error) {
    console.error("Get current user error:", error);
    return res
      .status(500)
      .json(createResponse(false, "Server error", null, error.message));
  }
};

// Logout user
export const logout = (req, res) => {
  try {
    req.logout((err) => {
      if (err) {
        console.error("Logout error:", err);
        return res
          .status(500)
          .json(createResponse(false, "Logout failed", null, err.message));
      }

      // Clear session
      req.session.destroy((err) => {
        if (err) {
          console.error("Session destroy error:", err);
        }

        // Clear cookies
        res.clearCookie("accessToken");
        res.clearCookie("refreshToken");
        res.clearCookie("sessionId");

        return res.json(createResponse(true, "Logged out successfully"));
      });
    });
  } catch (error) {
    console.error("Logout error:", error);
    return res
      .status(500)
      .json(createResponse(false, "Server error", null, error.message));
  }
};

// Refresh access token
export const refreshToken = (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

    if (!refreshToken) {
      return res
        .status(401)
        .json(
          createResponse(
            false,
            "Refresh token required",
            null,
            "No refresh token provided"
          )
        );
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_SECRET);

    // Generate new access token
    const newAccessToken = generateToken({
      id: decoded.id,
      email: decoded.email,
    });

    // Set new access token cookie
    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return res.json(
      createResponse(true, "Token refreshed successfully", {
        accessToken: newAccessToken,
      })
    );
  } catch (error) {
    console.error("Token refresh error:", error);
    return res
      .status(403)
      .json(
        createResponse(false, "Invalid refresh token", null, error.message)
      );
  }
};

const AuthController = {
  async register(req, res, next) {
    try {
      const { error, value } = registerSchema.validate(req.body);
      if (error) throw new Error(error.details[0].message);

      const { email, password, name } = value;

      const existingUser = await UserModel.findByEmail(email);
      if (existingUser) throw new Error("Email already in use");

      const newUser = await UserModel.create({ email, password, name });

      const token = UserModel.generateToken(newUser.id);

      req.session.userId = newUser.id;
      req.session.authenticated = true;

      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: "strict",
      });

      res.status(201).json({
        success: true,
        token: token,
        user: {
          id: newUser.id,
          name: newUser.name,
          email: newUser.email,
          createAt: newUser.create_at,
        },
      });
    } catch (error) {
      next(error);
    }
  },

  async login(req, res, next) {
    try {
      const { error, value } = loginSchema.validate(req.body);
      if (error) throw new Error(error.details[0].message);

      const { email, password } = value;

      const user = await UserModel.findByEmail(email);
      if (!user) throw new Error("Invalid Credantails");

      const isMatch = await UserModel.verifyPassword(password, user.password_hash);
      if (!isMatch) throw new Error("Invalid password");

      req.session.userId = user.id;
      req.session.authenticated = true;
      const token = UserModel.generateToken(user.id);

      res.cookie("token", token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: "strict",
      });

      res.json({
        success: true,
        token: token,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
        },
      });
    } catch (error) {
      next(error);
    }
  },

  async changePassword(req, res, next) {
    try {
      const { error, value } = changePasswordSchema.validate(req.body);
      if (error) throw new Error(error.details[0].message);

      const { currentPassword, newPassword } = value;

      if (!req.user) throw new Error("Not authenticated");
      const user = await UserModel.findByEmail(req.user.email);
      if (!user) throw new Error("Invalid Credantails");

      const isMatch = await UserModel.verifyPassword(
        currentPassword,
        user.password
      );
      if (!isMatch) throw new Error("Current password is incorrect");

      await UserModel.updatePassword(user.id, newPassword);
      res.json({
        success: true,
        message: "password updated successfully",
      });
    } catch (error) {
      next(error);
    }
  },

  async getCurrentLoginInfo(req, res, next) {
    try {
      if (!req.user) throw new Error("Not authenticated");

      const user = await UserModel.findById(req.user.id);
      if (!user) throw new Error("user not found");
      res.json({
        success: true,
        user,
      });
    } catch (error) {
      next(error);
    }
  },
};

export default AuthController;
