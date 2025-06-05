import express from "express";
import AuthController, { googleAuth, googleCallBack, refreshToken } from '../controllers/authController.js';
import { authenticateJWT } from '../middleware/authMiddleware.js';
import UserModel from '../models/userModel.js';

const router = express.Router();


router.get('/google', googleAuth);
router.get('/google/callback', googleCallBack);

// Auth routes
router.post("/register", AuthController.register);
router.post("/login", AuthController.login);
router.post('/logout', authenticateJWT, AuthController.logout);
router.put("/change-password", authenticateJWT, AuthController.changePassword);
router.get("/getme", authenticateJWT, AuthController.getMe);

// Token refresh
router.post('/refresh', refreshToken);

// JWT protected route example
router.get('/protected', authenticateJWT, (req, res) => {
  res.json({
    success: true,
    message: 'This is a protected route',
    user: req.user
  });
});

// Update last login
router.put('/update-last-login', authenticateJWT, async (req, res) => {
  const userId = req.user.id;
  await UserModel.updateLastLogin(userId);
  res.json({ success: true, message: 'Last login updated' });
});

export default router;