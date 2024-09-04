import express from 'express'
import User from '../modal/user.js'
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import Joi from 'joi'

const router = express.Router()

const userSchema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string().email().required(),
    phone: Joi.number().required(),
    password: Joi.string().min(6).required(),
});


router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email }).lean();
        if (!user) {
            return res.status(404).send({ message: "User not found" });
        }
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).send({ message: "Invalid password" });
        }
        const token = jwt.sign({ _id: user._id, email: user.email }, "MS");
        delete user.password;
        return res.status(200).send({ message: 'User found', user, token });
    } catch (err) {
        return res.status(400).send({ message: err.message });
    }
});
router.post('/signup', async (req, res) => {
    try {
        await userSchema.validateAsync(req.body);
        const { name, email, phone, password } = req.body;
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).send({ message: 'User already exists' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const userData = { name, email, phone, password: hashedPassword };
        const newUser = new User(userData);
        await newUser.save();
        const token = jwt.sign({ _id: newUser._id, email: newUser.email }, "MS");
        const userResponse = {
            _id: newUser._id,
            name: newUser.name,
            email: newUser.email,
            phone: newUser.phone,
            token
        };
        return res.status(200).send({ message: 'User Added Successfully!', user: userResponse });
    } catch (err) {
        return res.status(400).send({ message: err.message });
    }
});


export default router;