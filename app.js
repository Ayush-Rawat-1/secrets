import express from "express";
import bodyParser from "body-parser";
import dotenv from "dotenv";
import flash from "express-flash";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
dotenv.config();
import { db } from "./dbConfig.mjs";
import { initialize } from "./passportConfig.mjs";

initialize(passport);

const app=express();
const port=process.env.port || 3000;

//middleware
app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(flash());


function checkAuthenticated(req,res,next){
    if(req.isAuthenticated()){
        return res.redirect("/secrets");
    }
    next();
}

function checkNotAuthenticated(req,res,next){
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect("/");
}

app.get("/",(req,res)=>{
    res.render("home.ejs");
});

app.get("/login",checkAuthenticated,(req,res)=>{
    // flash sets a messages variable. passport sets the error message
    console.log(req.session.flash.error);
    res.render("login.ejs");
});

app.get("/register",checkAuthenticated,(req,res)=>{
    res.render("register.ejs");
});

app.get("/secrets",checkNotAuthenticated,(req,res)=>{
    res.render("secrets.ejs");
});

app.get("/logout",(req,res)=>{
    req.logOut((err)=>{
        if(err){
            console.log(err);
        }
        console.log("Successfully logged out");
    })
    res.redirect("/");
});

app.get("/submit",(req,res)=>{
    res.render("submit.ejs");
});

app.get('/auth/google', 
  passport.authenticate('google', { scope : ['profile', 'email'] }));
 
app.get('/auth/google/callback', 
  passport.authenticate('google', { failureRedirect: '/error' }),
  function(req, res) {
    // Successful authentication, redirect success.
    res.redirect('/secrets');
});

app.post("/register",async (req,res)=>{
    try{
        console.log(req.body);
        let {username , password} = req.body;
        let errors=[];
        if(!username || !password){
            errors.push({message: "Enter all credentials"});
        }
        if(password.length<6){
            errors.push({message: "Password must be at least 6 characters long"});
        }
        if(errors.length>0){
            res.render("register.ejs",{errors: errors});
        }else{
            try{
                const saltRounds=10;
                const hasshedPassword=await bcrypt.hash(password,saltRounds);
                console.log(hasshedPassword);
                console.log(hasshedPassword.length);
                const result=await db.query("INSERT INTO users(email,password) VALUES($1,$2) RETURNING *;",[username,hasshedPassword]);
                const newUser=result.rows[0];
                console.log(newUser);
                // req.logIn(newUser,(loginErr)=>{
                //     if(loginErr){
                //         console.log("Error R logging in : ",loginErr);
                //         throw loginErr;
                //     }
                // });
                passport.authenticate("local")(req, res, function(){
                    res.redirect("/secrets");
                });
                // res.redirect("/secrets");
            }catch(err){
                console.log("Error new user : ",err);
                res.redirect("/register");
            }
        }

    }catch(err){
        console.log("Failed to register user : ",err);
        res.status(500).json({error: "Failed to register user"});
        res.render("register.ejs",{errors: {message: "Failed to register"}});
    }
});

app.post("/login",passport.authenticate("local",{
    successRedirect: "/secrets",
    failureRedirect: "/login",
    failureFlash: true
}));

app.post("/submit",async (req,res)=>{
    try{
        console.log(req.body);
        try{
            await db.query("insert into secrets (uid,secret) values($1,$2);",[req.user.uid,req.body.secret]);
            console.log("req.user : ",req.user);
        }catch(err){
            console.log("Error submit : ",err);
            throw err;
        }
        res.redirect("/secrets");
    }catch(err){
        console.log("Error submit : ",err);
        res.status(500).json({error: "Failed to submit secret."});
    }
});

app.listen(port,()=>{
    console.log("Server is listening on port : ",port);
});