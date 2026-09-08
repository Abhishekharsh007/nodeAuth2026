import { Request, Response } from "express";
import { loginSchema, registerSchema } from "./auth.schema";
import { User } from "../../models/user.models";
import { checkPassword, hashPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendEMail } from "../../lib/email";
import { createAccessToken, createRefreshToken, verifyRefreshToken } from "../../lib/token";
import crypto from "crypto";

function getAppUrl() { 
    return process.env.APP_URL || `http://localhost:${process.env.PORT}`; 
}

export async function registerHandler(req: Request, res: Response) {
    try {
        const result = registerSchema.safeParse(req.body);
        if (!result) { 
            return res.status(400).json({
                message: 'Invalid data(email, password or name) is being provided by the user!'
            });
        }

        const { name, email, password } = result.data!;

        const normalizedEmail = email.toLowerCase().trim();

        const existingUser = await User.findOne({ email: normalizedEmail });
        if (existingUser) { 
            return res.status(409).json({
                message: 'Email is already in use! Please try with a different email!',
            });
        }

        const passwordHash = await hashPassword(password);

        const newlyCreatedUser = await User.create({
            email: normalizedEmail,
            passwordHash,
            name,
            role: 'user',
            isEmailVerified: false,
            twoFactorEnabled: false
        });

        // email verification part
        const verifyToken = jwt.sign(
            {
                sub: newlyCreatedUser.id,
            },
            process.env.JWT_ACCESS_SECRET!,
            {
                expiresIn: "1d",
            },
        );

        const verifyUrl = `${getAppUrl()}/auth/verify-email?token=${verifyToken}`;

        await sendEMail(
            newlyCreatedUser.email,
            "Verify your email",
            `
                <a>Please verify your email by clicking this link: </a>
                <a href="${verifyUrl}">${verifyUrl}</a> 
            `
        );

        return res.status(201).json({
            message: 'User Registered!',
            user: {
                id: newlyCreatedUser.id,
                email: newlyCreatedUser.email,
                role: newlyCreatedUser.role,
                isEmailVerified: newlyCreatedUser.isEmailVerified
            }
        });
    } catch (err) {
        console.log("Error is registering user!", err);
        return res.status(500).json({
            message: "Internal Server Error in registering user!",
        });
    }
}

export async function verifyEmailHandler(req: Request, res: Response) { 
    const token = req.query.token as string | undefined;
    if (!token) { 
        return res.status(400).json({ message: 'Verification token is missing!' });
    }

    try {
        const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET!) as {
            sub: string;
        }

        const user = await User.findById(payload.sub);
        if (!user) {
            return res.status(400).json({ message: "User not found in verify Email!" });
        }

        if (user.isEmailVerified) { 
            return res.json({ message: "Email is already verfied!" });
        }

        user.isEmailVerified = true;
        await user.save();

        return res.json({message: 'Email is now verified! You can login.'})
    } catch (err) {
        console.log("Error is verifying email!", err);
        return res.status(500).json({
            message: "Internal Server Error in Email Verification!",
        });
    }
}

export async function loginHandler(req: Request, res: Response) { 
    try {
        const result = loginSchema.safeParse(req.body);
        if (!result.success) { 
            return res.status(400).json({
                message: "Invalid data in login!",
            });
        }

        const { email, password } = result.data;

        const normalizedEmail = email.toLowerCase().trim();

        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            return res.status(400).json({
                message: "Invalid email or password in loginHandler!"
            });
        }

        const ok = await checkPassword(password, user.passwordHash);
        if (!ok) { 
            return res.status(400).json({ message: "Invalid password in loginHandler!" });
        }

        if (!user.isEmailVerified) {
            return res.json(403).json({ message: "Please Verify your email before login!" });
        }

        const accessToken = createAccessToken(
            user.id,
            user.role,
            user.tokenVersion
        );

        const refreshToken = createRefreshToken(user.id, user.tokenVersion);

        const isProd = process.env.NODE_ENV === 'production';

        res.cookie("refreshToken", refreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({
            message: "You are logged in!",
            accessToken,
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
                twoFactorEnabled: user.twoFactorEnabled,
            }
        });
    } catch (err) {
        console.log("Error in login!", err);
        return res.status(500).json({ message: "Internal Server Error in login!" });
    }
}

export async function refreshHandler(req: Request, res: Response) { 
    try {
        const token = req.cookies?.refreshToken as string | undefined;
        if (!token) { 
            return res.status(401).json({ message: "Refresh Token is missing!" });
        }

        const payload = verifyRefreshToken(token);

        const user = await User.findById(payload.sub);
        if (!user) {
            return res.status(401).json({ message: 'User not Found!' });
        }

        if (user.tokenVersion !== payload.tokenVersion) {
            return res.status(401).json({ message: 'Refresh token invalidated!' }); 
        }

        const newAccessToken = createAccessToken(
            user.id,
            user.role,
            user.tokenVersion
        );

        const newRefreshToken = createRefreshToken(user.id, user.tokenVersion);

        const isProd = process.env.NODE_ENV === 'production';

        res.cookie("refreshToken", newRefreshToken, {
            httpOnly: true,
            secure: isProd,
            sameSite: "lax",
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.status(200).json({
            message: "Token Refreshed!",
            accessToken: newAccessToken,
            user: {
                id: user.id,
                email: user.email,
                role: user.role,
                isEmailVerified: user.isEmailVerified,
                twoFactorEnabled: user.twoFactorEnabled
            }
        });
    } catch (err) {
        console.log("Error in refreshHandler!", err);
        return res.status(500).json({ message: "Internal Server Error in refreshHandler!" });
    }
}

export async function logoutHandler(_req: Request, res: Response) { 
    res.clearCookie("refreshToken", { path: "/" });

    return res.status(200).json({ message: "Logout successfully!" });
}

export async function forgotPasswordHandler(req: Request, res: Response) { 
    const { email } = req.body as { email?: string };
    if(!email) {
        return res.status(400).json({ message: 'Email is required!' });
    }

    const normalizedEmail = email.toLowerCase().trim();

    try {
        const user = await User.findOne({ email: normalizedEmail });
        if (!user) {
            return res.json({
                message: 'If an account with this email exists, we will send you a reset link!'
            });
        }

        const rawToken = crypto.randomBytes(32).toString('hex');

        const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');

        user.resetPasswordToken = tokenHash;
        user.resetPasswordExpires = new Date(Date.now() + 15 * 60 * 1000);

        await user.save();

        const resetUrl = `${getAppUrl()}/auth/reset-password?token=${rawToken}`;

        await sendEMail(
            user.email,
            "Verify your email",
            `
                <p>Please reset your password by clicking this link: </p>
                <a href="${resetUrl}">${resetUrl}</a> 
            `,
        );

        return res.json({
          message: "If an account with this email exists, we will send you a reset link!",
        });
    } catch (err) {
        console.log("Error in forgotPasswordHandler!", err);
        return res.status(500).json({
            message: "Internal Server Error in forgotPasswordHandler!"
        });
    }
}

export async function resetPasswordHandler(req: Request, res: Response) { 
    const { token } = req.query as { token?: string };
    const { password } = req.body as { password?: string };
    if (!token) { 
        return res.status(400).json({ message: 'Reset token is missing' });
    }
    if (!password || password.length < 6) { 
        return res.status(400).json({
            message: 'Password must be atleast 6 char long'
        });
    }

    try {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

        const user = await User.findOne({
            resetPasswordToken: tokenHash,
            resetPasswordExpires: { $gt: new Date() }  // expiry must be in future
        });

        if(!user) {
            return res.status(400).json({ message: 'Invalid or expired token!' });
        }

        const newPasswordHash = await hashPassword(password);
        user.passwordHash = newPasswordHash;

        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;

        user.tokenVersion = user.tokenVersion + 1;

        await user.save();

        return res.json({
            message: 'Password reset successfully!'
        });
    } catch (err) {
        console.log("Error in resetPasswordHandler!", err);
        return res.status(500).json({
            message: "Internal Server Error in resetPasswordHandler!",
        });
    }
}
