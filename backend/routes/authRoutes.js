import express from "express";
import {
  googleAuth,
  googleCallback,
  getCurrentUser,
  logout,
  refreshToken
} from '../controllers/authController.js';
import AuthController from '../controllers/authController.js';
import { isAuthenticated, authenticateJWT, authenticate } from '../middleware/authMiddleware.js';

const router = express.Router();

// console.log('Middleware check:', {
//   authenticate: typeof authenticate,
//   AuthController: {
//     register: typeof AuthController?.register,
//     login: typeof AuthController?.login,
//     changePassword: typeof AuthController?.changePassword
//   }
// });
// Google OAuth routes

router.get('/google', googleAuth);
router.get('/google/callback', googleCallback);

router.post("/register", AuthController.register);
router.post("/login", AuthController.login);
router.post("/get-current-login-info",authenticateJWT, getCurrentUser);
router.post("/change-password", authenticateJWT, AuthController.changePassword);


// User authentication routes
router.get('/user', isAuthenticated, getCurrentUser);
router.post('/logout', authenticateJWT, logout);
router.post('/refresh', refreshToken); 

// JWT protected route example
router.get('/protected', authenticateJWT, (req, res) => {
  res.json({
    success: true,
    message: 'This is a protected route',
    user: req.user
  });
}); 

export default router;