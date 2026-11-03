
'use strict';

// auth/passport.js - Google OAuth strategy

const passport = require('passport');
const { Strategy: GoogleStrategy } = require('passport-google-oauth20');
const { users, nextId } = require('../data');

// Verify Google user and return the appropriate application user
function verifyCallback(accessToken, refreshToken, profile, done) {
    try {

        // Scenario 1: Returning OAuth user
        // Check Google ID first because it is permanent.
        const existingGoogleUser = users.find(
            (user) => user.googleId === profile.id
        );

        if (existingGoogleUser) {
            return done(null, existingGoogleUser);
        }

        // Extract user details from Google profile
        const email = profile.emails[0].value;
        const name = profile.displayName;

        // Scenario 2: Existing local account
        // Find account using email.
        const existingUser = users.find(
            (user) => user.email === email
        );

        if (existingUser) {

            // Reject if Google email is not verified
            if (profile._json.email_verified !== true) {
                return done(null, false);
            }

            // Link Google ID to existing account
            existingUser.googleId = profile.id;

            return done(null, existingUser);
        }

        // Scenario 3: Brand-new user
        const newUser = {
            id: nextId(),
            googleId: profile.id,
            email: email,
            name: name,
            role: 'member'
        };

        // Save new user in the in-memory users array
        users.push(newUser);

        return done(null, newUser);

    } catch (error) {

        // Handle unexpected errors
        return done(error);
    }
}

// Configure Google OAuth strategy
passport.use(
    new GoogleStrategy(
        {
            clientID: process.env.GOOGLE_CLIENT_ID || 'test-client-id',
            clientSecret: process.env.GOOGLE_CLIENT_SECRET || 'test-client-secret',
            callbackURL: '/auth/google/callback',
        },
        verifyCallback
    )
);

// Export passport and verifyCallback for testing
module.exports = {
    passport,
    verifyCallback
};
