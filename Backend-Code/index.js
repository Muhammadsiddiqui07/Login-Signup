import express from 'express'
import router from './routes/index.js'
import mongoose from './db/index.js'
import cors from 'cors'

const app = express()
const port = 4000
const db = mongoose.connection;
app.use(express.json())
app.use(cors())


db.on('Error---->', console.error.bind(console, 'Connection error'))
db.once('open', function () {
    console.log('db connected!');
})

// app.use('/', (req, res, next) => {
//     if (req.query.apikey == '123') {
//         next();  
//     } else {
//         return res.status(401).send({ message: 'Not Allowed' });
//     }
// });

app.use('/api', router)


app.listen(port, () => {
    console.log(`server is running in port ${port}`);

})