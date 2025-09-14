require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser')
const connectDB = require('./config/db');
const authRoutes = require('./routes/auth');
const cors = require('cors');

const app = express();


connectDB();

//Middleware
app.use(cors({
    origin: '*',
    credentials: true 
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
 

//Routes
app.use('/api/auth', authRoutes);

//Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
