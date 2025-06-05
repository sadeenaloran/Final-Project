import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import dotenv from "dotenv";
import {
  findUserByGoogleId,
  createUser,
  findUserById,
} from "../models/userModel.js";

dotenv.config();

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
      scope: ["profile", "email"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await findUserByGoogleId(profile.id);
        if (user) {
          return done(null, user);
        }
        // CREATE the user in the database if not found!
        const newUser = {
          oauth_id: profile.id,
          email: profile.emails[0].value,
          name: profile.displayName,
          avatar: profile.photos && profile.photos[0] ? profile.photos[0].value : null,
          oauth_provider: "google",
        };
        user = await createUser(newUser); // <--- THIS LINE IS REQUIRED!
        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await findUserById(id);
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

export default passport;
