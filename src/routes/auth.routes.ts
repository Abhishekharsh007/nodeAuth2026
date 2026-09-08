import { Router } from "express";
import {
    forgotPasswordHandler,
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

export default router;
