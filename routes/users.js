const express = require('express');
const router = express.Router();
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const passport = require('passport');
//login page
router.get('/login', (req, res)=> res.render('login'));

//register page
router.get('/register', (req, res)=> res.render('register'));

//register handle
router.post('/register', (req, res)=>{
	const {name, email, password, password2 } = req.body;
	let errors = [];

	//check required fields
	if(!name || !email || !password || !password2){
		errors.push({msg: 'Please fill in all fields'});
	}

	//check password match
	if(password != password2){
		errors.push({msg: 'Password donot match'});
	}

	//check password length
	if(password.length < 6){
		errors.push({msg: 'Password should be at least 6 characters'});
	}

	//check user exist
	if(errors.length > 0){
		res.render('register',{
			errors,
			name,
			email,
			password,
			password2
		});
	}else{
		//validation pass
		User.findOne({email: email})
			.then(user => {
				if(user){
					//user exist
					errors.push({msg: 'Email already taken'});
					res.render('register',{
						errors,
						name,
						email,
						password,
						password2
					});
				}else{

					//create new
					const newUser = new User({
						name,
						email,
						password
					});
					//Hash password 
					bcrypt.genSalt(10, (err, salt)=> 
						bcrypt.hash(newUser.password, salt, (err, hash)=>{
							if(err) throw err;
							//set password hash
							newUser.password = hash;
							//save new user
							newUser.save()
								.then(user =>{
									req.flash('success_msg','You are now registered and can log in');
									res.redirect('/users/login');
								})
								.catch(err=>console.log(err));


					}));
				}
			});
	}
});

//login handle
router.post('/login',(req, res, next)=>{
	passport.authenticate('local', {
		successRedirect : '/dashboard',
		failureRedirect : '/users/login',
		failureFlash : true
	})(req, res, next);	
}); 

//logout handle
router.get('/logout', (req, res)=>{
	req.logout();
	req.flash('success_msg', 'You are logged out');
	res.redirect('/users/login');
});

module.exports = router;