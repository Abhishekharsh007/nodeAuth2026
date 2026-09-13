import { Router } from "express";
import {
    forgotPasswordHandler,
    googleAuthCallbackHandler,
    googleAuthStartHandler,
    loginHandler,
    logoutHandler,
    refreshHandler,
    registerHandler,
    resetPasswordHandler,
    verifyEmailHandler
} from "../controllers/auth/auth.controllers";

const router = Router();

router.post('/register', registerHandler);
router.get('/verify-email', verifyEmailHandler);
router.post('/login', loginHandler);
router.post('/refresh', refreshHandler);
router.post('/logout', logoutHandler);
router.post('/forgot-password/:token', forgotPasswordHandler);
router.post('/reset-password', resetPasswordHandler);
router.get('/google', googleAuthStartHandler);
router.get('/google/callback', googleAuthCallbackHandler);

export default router;
