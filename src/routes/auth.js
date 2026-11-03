
'use strict';

// routes/auth.js - OAuth entry points

const router = require('express').Router();
const { passport } = require('../auth/passport');
const { signToken } = require('../utils/jwt');

// Route 1: Start Google OAuth login
router.get(
    '/google',
    passport.authenticate('google', {
        scope: ['openid', 'email', 'profile'],
        session: false,
    }),
);

// Route 2: Google OAuth callback
router.get(
    '/google/callback',

    // Authenticate user using Google OAuth
    passport.authenticate('google', {
        session: false,
        failureRedirect: '/auth/failure',
    }),

    // Generate our application's JWT
    (req, res) => {

        // Get authenticated user details from Passport
        const token = signToken({
            sub: req.user.id,
            role: req.user.role
        });

        // Return JWT as JSON response
        res.json({ token });
    },
);

// Route 3: OAuth failure handler
router.get('/failure', (_req, res) => {
    res.status(401).json({
        error: {
            code: 'OAUTH_FAILED',
            message: 'Google login failed or was denied'
        }
    });
});

// Export router
module.exports = router;
