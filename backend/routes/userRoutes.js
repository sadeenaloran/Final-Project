import express from 'express';
import {
  getProfile,
  updateProfile,
  deleteAccount,
  getUsers
} from '../controllers/userController.js';
import { isAuthenticated, authenticateJWT } from '../middleware/authMiddleware.js';
import { validateUserProfile } from '../middleware/validation.js';

const router = express.Router();
router.use(isAuthenticated);
// for testing 
// User profile routes (session-based authentication)
router.get('/profile', getProfile);
router.put('/profile', isAuthenticated, validateUserProfile, updateProfile);
router.delete('/account', isAuthenticated, deleteAccount);

// JWT-based routes
router.get('/profile-jwt', authenticateJWT, getProfile);
router.put('/profile-jwt', authenticateJWT, validateUserProfile, updateProfile);

// Admin routes
router.get('/all', isAuthenticated, getUsers);

export default router;