import express from 'express';
import jwt from 'jsonwebtoken';
import passport from 'passport';
import bcrypt from "bcryptjs";

const Router = express.Router();

//models
import { UserModel } from "../../database/user/index";
import getUserStatus from '../../middlewares/getUserStatus';

//validation

import { ValidateSignup, ValidateSignin, ValidateEmail } from "../../validation/auth";
import { sendMail } from '../../controllers/emailSender';


/* 
Route     /loaduser
descrip   load user using token
params    none
access    public
method    post

*/

Router.get("/loaduser", getUserStatus, async (req, res) => {
  try {
    if (req.user) {
      return res.status(200).json({ success: true, user: req.user });
    }
    else {
      throw new Error("Something's Wrong, Try Signing in again");
    }

  } catch (error) {
    return res.status(500).json({ message: error.message, success: false });
  }
})
/* 
Route     /signup
descrip   signup with email and password
params    none
access    public
method    post

*/

Router.post("/signup", async (req, res) => {
  try {
    await ValidateSignup(req.body.credentials);
    const { email } = req.body.credentials;
    const user = await UserModel.findOne({ email })
    if (!user) {
      let { city } = req.body.credentials;
      city = city.toLowerCase();
      const data = { ...req.body.credentials, city };
      //DB
      const newUser = await UserModel.create(data);

      //JWT AUth Token
      const token = newUser.generateJwtToken();

      return res.status(200).json({ token, user: newUser, success: true });
    }
    throw new Error('User Already Exists');

  } catch (error) {
    return res.status(500).json({ message: error.message, success: false });
  }
})

/* 
Route     /signin
descrip   signin with userName and password
params    none
access    public
method    post

*/



Router.post("/signin", async (req, res) => {
  try {
    const { password, email } = req.body.credentials;
    await ValidateSignin(req.body.credentials);

    let user = await UserModel.findByEmailAndPassword({ email, password });
    user.password = null;
    //JWT AUth Token
    const token = user.generateJwtToken();

    return res.status(200).json({ token, success: true, user: user });

  } catch (error) {
    return res.status(500).json({ message: error.message, success: false });
  }
})


/* 
Route     /google
descrip   Google signin/signup 
params    none
access    public
method    GET
*/

Router.get("/google", passport.authenticate("google", {
  scope: [
    "https://www.googleapis.com/auth/userinfo.profile",
    "https://www.googleapis.com/auth/userinfo.email"
  ],
}));

/* 
Route     /google/callback
descrip   Google signin/signup callback
params    none
access    public
method    GET

*/

Router.get("/google/callback", passport.authenticate("google", {
  failureRedirect: "/"
}), (req, res) => {
  try {
    res.set('Access-Control-Allow-Origin', 'https://our-foodapp.vercel.app/');
    const token = req.session.passport.user.token;
    res.redirect(`https://our-foodapp.vercel.app/auth/google/${token}`);
    //  res.json({token: req.session.passport.user.token, success:true, user: req.session.passport.user.user});
  } catch (error) {
    return res.status(500).json({ message: error.message, success: false });
  }

});







/* 
Route     /forget-pass
descrip   forget pass, so lets change it
params    email
access    public
method    GET

*/

Router.get("/forgot-pass", async (req, res) => {
  try {
    const { email,type } = req.query;
    // console.log(type);
    if(type!=='user' && type!=='restaurant'){
      return res.status(400).json({message:"Invalid Params",success:false});
    }
    await ValidateEmail({email});
    const user = await UserModel.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not Found", success: false });
    }
    const token = jwt.sign({id:user._id.toString(),email:user.email},'forget-pass',{expiresIn:"10m"});
    
    await sendMail(email,'Reset Pass for your Food-App',`<h4>Someone (hopefully you) has requested a password reset for your Food-app account. Follow the link below to set a new password:</h4><a href="https://${type==='user'?'our-foodapp.vercel.app':'restaurant-app-azure.vercel.app'}/auth/reset?token=${token}">Reset Password Here</a>`)
    
    return res.status(200).json({message:"email sent successfully", success:true});
  } catch (error) {
    return res.status(500).json({ message: error.message, success: false });
  }


})

Router.put('/reset-pass',async (req,res)=>{
  try {
    const {token, pass} = req.body;
    const {id, email} = jwt.verify(token,'forget-pass');
    
    const user = await UserModel.findById(id);
    if(user.email!== email){
      return res.status(401).json({message:"Not Authorized", success:false});
    }
   
  const salt= await bcrypt.genSalt(10);

  const secPass= await bcrypt.hash(pass,salt);
    const updatedUser =  await UserModel.findByIdAndUpdate(id,{
      password: secPass
    },{
      new:true,
      upsert:true
    })
    res.status(200).json({message:"Password changed successfully",success:true});
  } catch (error) {
    return res.status(500).json({ message: error.message, success: false });
  }
})


export default Router;