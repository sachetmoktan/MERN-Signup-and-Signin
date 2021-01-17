const express = require('express');
const router = express.Router();
const auth = require('../../middleware/authmiddleware');
const User = require('../../models/User');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator/check');
const bcrypt = require('bcryptjs');

router.get( '/', auth, async (req, res) => {   
    try {
        const sur = await User.findById(req.user.id).select('-password');

        res.json(sur);
    }
    catch(err){
        console.error(err.message);
        res.status(500).send('Server Error');
    }
} );

router.post( '/', [
                        check('email', 'Please include a valid email').isEmail(),
                        check('password', 'Password is required').exists()
    ],
    async (req, res) => {                          
        const errors = validationResult(req);    

        if(!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { email, password } = req.body;

        try {

            // See if user exists
            let usr = await User.findOne( { email } );
            if(!usr) {   
            return res.status(400).json( {errors: [{ msg: 'Invalid credentials e' }] } );
            }
            const isMatch = await bcrypt.compare(password, usr.password);

            if(!isMatch) {
                return res.status(400).json( {errors: [{ msg: 'Invalid credentials p' }] } );
            }

            const payload = {    
                uzz: {          
                    id:usr.id   
                }
            }

            jwt.sign(payload, config.get('jwtSecret'), { expiresIn: 360000 }, (err, token) => {
                if(err) throw err;
                res.json({ token });
            } );
        }
        catch(err){
        console.error(err.message);
        res.status(500).send('Server Error');
        }


} );
module.exports = router;