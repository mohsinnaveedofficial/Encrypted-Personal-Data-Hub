const express = require('express');
const sql = require('mssql');
const app = express();
const path = require("path")
const ejsmate = require("ejs-mate");
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const JWT_SECRET = "c48f1b935f2e4b76a2e92g0d8a1ee2f3e42e77b8d59c489f879f7e96c0aabf12";
const methodOverride = require('method-override');
const expresserror=require("./expresserror")


app.set("view engine", "ejs");
app.engine("ejs", ejsmate);
app.set("views", path.join(__dirname, "/views"));
app.use(express.static(path.join(__dirname, "public")));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cookieParser());
app.use(methodOverride("_method"))



const port = 8080;
app.listen(port, () => {
    console.log("server is running at port 8080");
});




const verifytoken = (req, res, next) => {

    const token = req.cookies.token;
    if (!token) return res.redirect("/auth");

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.redirect("/auth");

        req.user = decoded;
        next();
    });
}

(async () => {
    try {
        await sql.connect({
            user: 'myuser',
            password: '12345678',
            database: 'decentralized_db',
            server: 'localhost',
            port: 1433,
            options: {
                encrypt: false,
                trustServerCertificate: true
            }
        });




    } catch (err) {
        console.error('Query error', err);
    }
})();




app.get("/auth", async (req, res) => {

    res.render("auth.ejs", { hidenavbar: true, hidefooter: true })
})
app.get("/home", verifytoken, (req, res) => {
    const public_key = req.cookies.public_key;
    const token = req.cookies.token;
    const decode = jwt.verify(token, JWT_SECRET);
    const user_id = decode.user_id;

sql.query(`select * from db_owner.Users where  user_id='${user_id}'`,(err,result)=>{
    const data = result.recordset[0];
    res.render("home.ejs", {
        hidenavbar: false,
        hidefooter: false,
        user_id,
        public_key,
        token,
        data
    });
})
    


});

// post request for login 
app.post("/login", (req, res,next) => {
    let { email, password } = req.body.login;

    sql.query(`select * from Users where email = '${email}'`, async (err, result) => {
        if (err) {
           
            // return res.status(500).send("Database error")
            return next( new expresserror("database error"));
        } else {
            if (result.recordset.length < 1) {
                
                return next(new expresserror(500,"No user found"));
            }

            const user = result.recordset[0];

            // console.log(user.password_hash)

            const ispassmatch = await bcrypt.compare(password, user.password_hash);
            if (!ispassmatch) {
                // return res.status(401).send("Password Incorrect");
                return next( new expresserror(401,"Password Incorrect"));
            }
            try {
                const public_key = user.public_key;
                const encryptedPrivateKey = user.private_key_enc;
                const [ivHex, encryptedHex] = encryptedPrivateKey.split(":");
                const iv = Buffer.from(ivHex, "hex");
                const encryptedData = Buffer.from(encryptedHex, "hex");

                const aesKey = crypto.createHash("sha256").update(password).digest();

                const decipher = crypto.createDecipheriv("aes-256-cbc", aesKey, iv);
                let decryptedPrivateKey = decipher.update(encryptedData, "hex", "utf8");
                decryptedPrivateKey += decipher.final("utf8");



                const token = jwt.sign({ user_id: user.user_id }, JWT_SECRET, { expiresIn: "1h" });

               

                res.cookie("token", token, {

                    secure: false,
                    maxAge: 3600000
                })
                res.cookie("public_key", public_key, {

                    secure: false,
                    maxAge: 3600000
                })

                res.redirect("/home");
            } catch (error) {
                return next( new expresserror(500,"Error decrypting private key"));

            }



        }




    })

})


app.post("/register", async (req, res,next) => {
    let { name, email, phone_number, password, confirmpassword } = req.body.register;
    if(name == null ||email==null||phone_number==null||password==null||confirmpassword==null){
        return next(new expresserror(400,"Enter the valid data"));
    }
    else{
    if (password === confirmpassword) {


        try {
            let ouptutUser_id;
            const passwordHash = await bcrypt.hash(password, 10);
            const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
                modulusLength: 2048,
                publicKeyEncoding: {
                    type: "spki",
                    format: "pem"
                },
                privateKeyEncoding: {
                    type: "pkcs8",
                    format: "pem"
                }
            });

            const aesKey = crypto.createHash("sha256").update(password).digest();
            const iv = crypto.randomBytes(16);
            const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
            let encryptedPrivateKey = cipher.update(privateKey, "utf8", "hex");
            encryptedPrivateKey += cipher.final("hex");
            encryptedPrivateKey = iv.toString("hex") + ":" + encryptedPrivateKey;




            const query = `insert into Users(name,email,password_hash,public_key,private_key_enc) OUTPUT INSERTED.user_id values ('${name}', '${email}', '${passwordHash}', '${publicKey}', '${encryptedPrivateKey}')`;
            await sql.query(query, (err, result) => {
                if (err) {
                    return next(new expresserror(500,"error saving user"));
                    // return res.status(500).send("error saving user")
                } else {

                    ouptutUser_id = result.recordset[0].user_id;

                    sql.query(`insert into UserProfile(user_id,fullname,email,phone_number) values ('${ouptutUser_id}','${name}','${email}','${phone_number}')`, (err, result) => {
                        if (err) {
                            console.log(err);
                            return next(new expresserror(500,"authenication failed"));
                        }
                        else {
                            return res.render("auth.ejs", { hidenavbar: true, hidefooter: true })

                        }
                    })

                }
            })







        } catch (err) {
            return next(new expresserror(500,"Internal server error"));
           
        }





    } else {
        return next(new expresserror(400,"Password not same"));
    }}

})





app.get("/add-data", verifytoken, (req, res,next) => {
    const token = req.cookies.token;
    const decode = jwt.verify(token, JWT_SECRET);
    const user_id = decode.user_id;
    sql.query('select data_id , type_name from DataTypes', (err, results) => {
        if (err) {
            return next( new expresserror(500,"Error Not fetching the datatypes"));
            
        }
        const data = results.recordset
        const public_key = req.cookies.public_key;
        res.render("add-data.ejs", { hidenavbar: false, hidefooter: false, data, public_key, user_id });

    })

})

app.post("/add-data", verifytoken, async (req, res,next) => {
    const token = req.cookies.token;
    const decode = jwt.verify(token, JWT_SECRET);
    const user_id = decode.user_id;

    const { type, encrypted_data, iv, key_enc } = req.body;

    if (!user_id || !type || !encrypted_data || !iv || !key_enc) {
        return next( new expresserror(400,"Missing required fields"));
    
    }

    try {
        const request1 = new sql.Request();
        request1.input("user_id", sql.Int, parseInt(user_id));
        request1.input("type", sql.Int, parseInt(type));
        request1.input("encrypted_data", sql.NVarChar(sql.MAX), encrypted_data);
        request1.input("iv", sql.VarChar(255), iv);

        const insertUserDataQuery = `
        INSERT INTO UserData (user_id, data_type_id, encrypted_data, iv)
        OUTPUT INSERTED.data_id
        VALUES (@user_id, @type, @encrypted_data, @iv);
      `;

        const result1 = await request1.query(insertUserDataQuery);
        const user_data_id = result1.recordset[0].data_id;


        const request2 = new sql.Request();
        request2.input("user_id", sql.Int, parseInt(user_id));
        request2.input("key_enc", sql.NVarChar(sql.MAX), key_enc);
        request2.input("data_id", sql.Int, user_data_id);

        const insertEncryptionKeyQuery = `
        INSERT INTO Encryption_Keys (user_id, key_enc, data_id)
        VALUES (@user_id, @key_enc, @data_id);
      `;

        await request2.query(insertEncryptionKeyQuery);

        res.redirect("/add-data");
    } catch (err) {
        return next(new expresserror(500,"Internal server error"));
        
    }
});




app.get("/get-data", verifytoken, async (req, res,next) => {


    const token = req.cookies.token;
    
    const decode = jwt.verify(token, JWT_SECRET);
    const user_id = decode.user_id;

    const result = await sql.query(`
     select * from getDataById ( '${user_id} ' ); 
    `)

    const private_key = await sql.query(`select private_key_enc from  db_owner.Users
    where user_id='${user_id}'`)

   
    const private_key_enc = private_key.recordset[0].private_key_enc
    const user_data = result.recordset;
    

    res.render("get-data.ejs", { hidenavbar: false, hidefooter: false, user_data, private_key_enc });

})

app.get("/logout", (req, res) => {
    res.clearCookie("token");
    res.clearCookie("public_key");
    res.redirect("/auth")
})


app.delete("/data/:id", (req, res,next) => {
    let { id } = req.params;



    sql.query(`exec dbo.delete_data '${id}' `, (err, result) => {
        if (err) {
            return next(new expresserror(500,"Deletion error"));

        } else {
            return res.redirect("/get-data")
        }
    })

})


app.post("/share-data/:id", verifytoken, (req, res) => {

    let { id } = req.params
    res.render("share-data.ejs", { hidefooter: false, hidenavbar: false, id: id });
})





app.post("/send-share-data/:id", verifytoken, async (req, res,next) => {
    try {
        const token = req.cookies.token;
        const decode = jwt.verify(token, JWT_SECRET);
        const sender_user_id = decode.user_id;

        const { receptionist_email, password } = req.body;
        const { id: data_id } = req.params;


        const dataResult = await sql.query(`
            SELECT encrypted_data, iv, Encryption_Keys.key_enc
            FROM UserData
            JOIN Encryption_Keys ON UserData.data_id = Encryption_Keys.data_id
            WHERE UserData.data_id = '${data_id}'
        `);

        if (dataResult.recordset.length === 0) {
            return next( new expresserror(404,"Data not found"));
        }

        const { encrypted_data, iv, key_enc } = dataResult.recordset[0];


        const userResult = await sql.query(`
            SELECT user_id, public_key
            FROM db_owner.Users
            WHERE email = '${receptionist_email}'
        `);

        if (userResult.recordset.length === 0) {
           
            return next( new expresserror(404,"Recipient user not found"));
        }

        const { user_id: receiver_user_id, public_key: receiver_public_key_pem } = userResult.recordset[0];

        const privateKeyResult = await sql.query(`
            SELECT private_key_enc
            FROM db_owner.Users
            WHERE user_id = '${sender_user_id}'
        `);

        if (privateKeyResult.recordset.length === 0) {
            return next( new expresserror(404,"Sender key not found"));
        }

        const sender_private_key_enc = privateKeyResult.recordset[0].private_key_enc;



        const [ivHex, encryptedHex] = sender_private_key_enc.split(":");

        const ivBuffer = Buffer.from(ivHex, 'hex');
        const encryptedPrivateKeyBuffer = Buffer.from(encryptedHex, 'hex');

        const aesKey = crypto.createHash('sha256').update(password).digest();

        const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, ivBuffer);
        let decryptedPrivateKey = decipher.update(encryptedPrivateKeyBuffer);
        decryptedPrivateKey = Buffer.concat([decryptedPrivateKey, decipher.final()]);

        const sender_private_key_pem = decryptedPrivateKey.toString();


        const decryptedAESKey = crypto.privateDecrypt(
            {
                key: sender_private_key_pem,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            Buffer.from(key_enc, 'base64')
        );


        const encryptedAESKeyForReceiver = crypto.publicEncrypt(
            {
                key: receiver_public_key_pem,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            decryptedAESKey
        );


        await sql.query(`
            INSERT INTO SharedData (sender_id, receiver_id, encrypted_data, iv, key_enc)
            VALUES (
                '${sender_user_id}',
                '${receiver_user_id}',
                '${encrypted_data}',
                '${iv}',
                '${encryptedAESKeyForReceiver.toString('base64')}'
            )
        `);

        return res.redirect("/get-data")

    } catch (error) {
        return next( new expresserror(500,"An error occurred while sharing data"));
        
    }
});



app.get("/get-shared-data", verifytoken, async (req, res,next) => {
   
    const token = req.cookies.token;
    const decode = jwt.verify(token, JWT_SECRET);
    const user_id = decode.user_id;
    try {
        const privateKeyResult = await sql.query(`SELECT private_key_enc FROM db_owner.Users WHERE user_id = '${user_id}'`);
        const sender_private_key_enc = privateKeyResult.recordset[0]?.private_key_enc;

        if (!sender_private_key_enc) {
            return next( new expresserror(404,"key not found"));
        }




        await sql.query(`select SharedData.*, u.email,u.name from SharedData 
    join db_owner.Users u
    on u.user_id=SharedData.sender_id
    where receiver_id ='${user_id}' `

            , (err, result) => {
                if (err) {
                    return next( new expresserror(500,"Data fetching error"));
                }
                else {
                    const data = result.recordset;
                    // console.log("private key" ,sender_private_key_enc)
                    // console.log(data);
                    return res.render("get-shared-data.ejs", { hidefooter: false, hidenavbar: false, data, private_key_enc: sender_private_key_enc });
                }
            })


    } catch (err) {
        return next( new expresserror(500,"Error Found"));
        
    }


})


app.use((err,req,res,next)=>{

  
let {status=500 ,message="something went wrong"}=err;


res.status(status).render("error.ejs",{hidefooter:false,hidenavbar:true, message});

})