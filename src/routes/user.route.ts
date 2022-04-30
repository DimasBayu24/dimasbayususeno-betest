import express from 'express';
import {
  loginHandler,
  logoutHandler,
  refreshAccessTokenHandler,
  registerHandler,
  updateHandler,
  removeHandler,
  findbyAccountHandler,
  findbyIdentityHandler
} from '../controllers/auth.controller';
import {
  getAllUsersHandler,
  getMeHandler,
} from '../controllers/user.controller';
import { deserializeUser } from '../middleware/deserializeUser';
import { requireUser } from '../middleware/requireUser';
import { validate } from '../middleware/validate';
import { createUserSchema, loginUserSchema } from '../schema/user.schema';

const router = express.Router();

// Register user route
router.post('/register', validate(createUserSchema), registerHandler);

// Login user route
router.post('/login', validate(loginUserSchema), loginHandler);

// Update user route
router.patch('/update/:id', updateHandler);

// Delete user route
router.delete('/delete/:id', removeHandler);

// Find by account user route
router.get('/account/:accountNumber', findbyAccountHandler);

// Find by identity user route
router.get('/identity/:identityNumber', findbyIdentityHandler);

// Refresh access toke route
router.get('/refresh', refreshAccessTokenHandler);

router.use(deserializeUser, requireUser);

// Logout User
router.get('/logout', logoutHandler);

// Admin Get Users route
router.get('/', getAllUsersHandler);

// Get my info route
router.get('/me', getMeHandler);

export default router;
