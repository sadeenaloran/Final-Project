import session from 'express-session';
import dotenv from 'dotenv';

dotenv.config();

const sessionConfig = {
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: process.env.NODE_ENV === 'production', 
    httpOnly: true, 
    maxAge: 24 * 60 * 60 * 1000, 
    sameSite: 'lax' 
  },
  name: 'sessionId', 
  rolling: true 
};

export default sessionConfig;