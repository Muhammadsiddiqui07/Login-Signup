import express from 'express';
import users from '../constant/user.js'

const router = express.Router()

router.use('/user', users)


export default router;  