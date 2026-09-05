import { Request, Response } from "express";
import { registerSchema } from "./auth.schema";
import { User } from "../../models/user.models";
import { hashPassword } from "../../lib/hash";
import jwt from "jsonwebtoken";
import { sendMail } from "../../lib/email";

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

        const verifyUrl = `${getAppUrl}/auth/verify-email?token=${verifyToken}`;

        await sendMail(
            newlyCreatedUser.email,
            "Verify your email",
            `
            <p>Please verify your email by clicking this link:</p>
            <p><a href="${verifyUrl}">${verifyUrl}</a></p>
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
