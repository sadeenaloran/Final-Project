import jwt from "jsonwebtoken";
import UserModel, { findUserById } from "../models/userModel.js";
import {
  registerSchema,
  loginSchema,
  changePasswordSchema,
} from "../utils/validation.js";

import passport from "../config/passport.js";
import { generateToken, generateRefreshToken } from "../utils/jwt.js";
import { sanitizeUser, createResponse } from "../utils/helpers.js";

export const googleAuth = passport.authenticate("google", {
  scope: ["profile", "email"],
  session: false,
});

const AuthController = {
  googleAuthCallback: async (req, res) => {
    try {
      const token = UserModel.generateToken(req.user.id, req.user.role);
      await UserModel.updateLastLogin(req.user.id);

      res.redirect(
        `${process.env.CORS_ORIGIN}/auth/success?` +
          `token=${token}&` +
          `id=${req.user.id}&` +
          `name=${encodeURIComponent(req.user.name)}&` +
          `email=${encodeURIComponent(req.user.email)}&` +
          `avatar=${encodeURIComponent(req.user.avatar || "")}&` +
          `role=${req.user.role}`
      );
    } catch (error) {
      console.error(`Google callback error: ${error.message}`);
      res.redirect(`${process.env.CORS_ORIGIN}/login?error=oauth_failed`);
    }
  },

  async linkGoogleAccount(req, res, next) {
    try {
      const { token: googleToken } = req.body;
      if (!googleToken) {
        return res.status(400).json({ success: false, message: "Google token is required" });
      }

      // You need to implement or import this.verifyGoogleToken!
      const googleUser = await AuthController.verifyGoogleToken(googleToken);
      if (!googleUser) {
        return res.status(400).json({ success: false, message: "Invalid Google token" });
      }

      // Link to existing account
      const updatedUser = await UserModel.linkOAuthAccount(req.user.id, {
        provider: "google",
        providerId: googleUser.sub,
        email: googleUser.email,
      });

      res.json({
        success: true,
        user: {
          id: updatedUser.id,
          name: updatedUser.name,
          email: updatedUser.email,
          oauthProvider: updatedUser.oauth_provider,
          role: updatedUser.role,
        },
      });
    } catch (error) {
      next(error);
    }
  },

  register: async (req, res, next) => {
    try {
      const { error, value } = registerSchema.validate(req.body);
      if (error) {
        return res
          .status(400)
          .json({ success: false, message: error.details[0].message });
      }

      const {
        name,
        email,
        password,
        confirm_password,
        role = "student",
      } = value;

      const existingUser = await UserModel.findByEmail(email);
      if (existingUser) {
        return res
          .status(409)
          .json({ success: false, message: "Email already in use" });
      }
      const newUser = await UserModel.create({ name, email, password, role });

      const token = UserModel.generateToken(newUser.id, newUser.role);

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
          role: newUser.role,
          createAt: newUser.create_at,
        },
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: `Registration error: ${error.message}`,
      });
    }
  },

  login: async (req, res, next) => {
    try {
      const { error, value } = loginSchema.validate(req.body);
      if (error) {
        return res
          .status(400)
          .json({ success: false, message: error.details[0].message });
      }
      const { email, password } = value;

      const user = await UserModel.findByEmail(email);
      if (!user) {
        return res
          .status(401)
          .json({ success: false, message: "Invalid Credentials" });
      }

      const isMatch = await UserModel.verifyPassword(
        password,
        user.password_hash
      );
      if (!isMatch) {
        return res
          .status(401)
          .json({ success: false, message: "Invalid password" });
      }

      req.session.userId = user.id;
      req.session.authenticated = true;
      const token = UserModel.generateToken(user.id, user.role);
      await UserModel.updateLastLogin(user.id);

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
          role: user.role,
          createAt: user.create_at,
        },
      });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  },

  logout: async (req, res, next) => {
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

          return res.status(200).json({
            success: true,
            message: "Logged out successfully",
          });
        });
      });
    } catch (error) {
      console.error("Logout error:", error);
      return res
        .status(500)
        .json(createResponse(false, "Server error", null, error.message));
    }
  },

  getMe: async (req, res, next) => {
    try {
      if (!req.user || !req.user.id) {
        return res
          .status(401)
          .json({ success: false, message: "User not authenticated" });
      }
      const user = await findUserById(req.user.id);
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }
      res.json({
        success: true,
        user: {
          id: user.id,
          name: user.name,
          email: user.email,
          role: user.role,
          avatar: user.avatar, // Include avatar in response
        },
      });
    } catch (err) {
      next(err);
    }
  },

  changePassword: async (req, res, next) => {
    try {
      const { error, value } = changePasswordSchema.validate(req.body);
      if (error) {
        return res
          .status(400)
          .json({ success: false, message: error.details[0].message });
      }

      const { currentPassword, newPassword, confirmPassword } = value;
      const userId = req.user.id;

      if (!req.user) {
        return res
          .status(401)
          .json({ success: false, message: "Not authenticated" });
      }

      const user = await UserModel.findByEmail(req.user.email);
      if (!user) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      const isMatch = await UserModel.verifyPassword(
        currentPassword,
        user.password_hash
      );

      if (!isMatch) {
        return res
          .status(401)
          .json({ success: false, message: "Current password is incorrect" });
      }

      await UserModel.updatePassword(userId, newPassword);
      res.json({
        success: true,
        message: "Password updated successfully",
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        message: `Password change error: ${error.message}`,
      });
    }
  },
};

// Add a static or utility method for verifying Google token
AuthController.verifyGoogleToken = async function (googleToken) {
  const { OAuth2Client } = await import('google-auth-library');
  const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
  const ticket = await client.verifyIdToken({
    idToken: googleToken,
    audience: process.env.GOOGLE_CLIENT_ID,
  });
  return ticket.getPayload();
};

// Refresh access token (named export, outside the object)
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

export default AuthController;
