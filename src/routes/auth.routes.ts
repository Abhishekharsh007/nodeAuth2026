import { Router } from "express";
import {
    loginHandler,
    logoutHandler,
    refreshHandler,
    registerHandler,
    verifyEmailHandler
} from "../controllers/auth/auth.controllers";

const router = Router();

router.post('/register', registerHandler);
router.get('/verify-email', verifyEmailHandler);
router.post('/login', loginHandler);
router.post('/refresh', refreshHandler);
router.post('/logout', logoutHandler);

export default router;
