const express = require('express')
const mysql = require('mysql2')
const app = express()
const port = 4000

const https = require('https');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const SECRET_KEY = 'UX23Y24%@&2aMb';

const fileupload = require('express-fileupload');
const path = require('path');
const crypto = require('crypto');

// Load SSL certificates
const privateKey = fs.readFileSync('privatekey.pem', 'utf8');
const certificate = fs.readFileSync('certificate.pem', 'utf8');
const credentials = { key: privateKey, cert: certificate };

// Import CORS library
const cors = require('cors');

//Database(MySql) configulation
const db = mysql.createConnection(
    {
        host: "localhost",
        user: "root",
        password: "1234",
        database: "shopdee"
    }
)
db.connect()

//Middleware (Body parser)
app.use(express.json())
app.use(express.urlencoded ({extended: true}))
app.use(cors());
app.use(fileupload());

//Hello World API
app.get('/', function(req, res){
    res.send('Hello World!')
});


/*############## CUSTOMER ##############*/
// Register
app.post('/api/register', 
    function(req, res) {  
        const { username, password, firstName, lastName } = req.body;
        
        //check existing username
        let sql="SELECT * FROM customer WHERE username=?";
        db.query(sql, [username], async function(err, results) {
            if (err) throw err;
            
            if(results.length == 0) {
                //password and salt are encrypted by hash function (bcrypt)
                const salt = await bcrypt.genSalt(10); //generate salte
                const password_hash = await bcrypt.hash(password, salt);        
                                
                //insert customer data into the database
                sql = 'INSERT INTO customer (username, password, firstName, lastName) VALUES (?, ?, ?, ?)';
                db.query(sql, [username, password_hash, firstName, lastName], (err, result) => {
                    if (err) throw err;
                
                    res.send({'message':'ลงทะเบียนสำเร็จแล้ว','status':true});
                });      
            }else{
                res.send({'message':'ชื่อผู้ใช้ซ้ำ','status':false});
            }

        });      
    }
);


//Login
app.post('/api/login',
    async function(req, res){
        //Validate username
        const {username, password} = req.body;                
        let sql = "SELECT * FROM customer WHERE username=? AND isActive = 1";        
        let customer = await query(sql, [username, username]);        
        
        if(customer.length <= 0){            
            return res.send( {'message':'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง','status':false} );
        }else{            
            customer = customer[0];
            custID = customer['custID'];               
            password_hash = customer['password'];       
        }

        //validate a number of attempts 
        let loginAttempt = 0;
        sql = "SELECT loginAttempt FROM customer WHERE username=? AND isActive = 1 ";        
        sql += "AND lastAttemptTime >= CURRENT_TIMESTAMP - INTERVAL 24 HOUR ";        
        
        row = await query(sql, [username, username]);    
        if(row.length > 0){
            loginAttempt = row[0]['loginAttempt'];

            if(loginAttempt>= 3) {
                return res.send( {'message':'บัญชีคุณถูกล๊อก เนื่องจากมีการพยายามเข้าสู่ระบบเกินกำหนด','status':false} );    
            }    
        }else{
            //reset login attempt                
            sql = "UPDATE customer SET loginAttempt = 0, lastAttemptTime=NULL WHERE username=? AND isActive = 1";                    
            await query(sql, [username, username]);               
        }              
        

        //validate password       
        if(bcrypt.compareSync(password, password_hash)){
            //reset login attempt                
            sql = "UPDATE customer SET loginAttempt = 0, lastAttemptTime=NULL WHERE username=? AND isActive = 1";        
            await query(sql, [username, username]);   

            //get token
            const token = jwt.sign({ custID: custID, username: username }, SECRET_KEY, { expiresIn: '1h' });                

            customer['token'] = token;
            customer['message'] = 'เข้าสู่ระบบสำเร็จ';
            customer['status'] = true;

            res.send(customer);            
        }else{
            //update login attempt
            const lastAttemptTime = new Date();
            sql = "UPDATE customer SET loginAttempt = loginAttempt + 1, lastAttemptTime=? ";
            sql += "WHERE username=? AND isActive = 1";                   
            await query(sql, [lastAttemptTime, username, username]);           
            
            if(loginAttempt >=2){
                res.send( {'message':'บัญชีคุณถูกล๊อก เนื่องจากมีการพยายามเข้าสู่ระบบเกินกำหนด','status':false} );    
            }else{
                res.send( {'message':'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง','status':false} );    
            }            
        }

    }
);


// Function to execute a query with a promise-based approach
function query(sql, params) {
    return new Promise((resolve, reject) => {
      db.query(sql, params, (err, results) => {
        if (err) {
          reject(err);
        } else {
          resolve(results);
        }
      });
    });
}

// List customers
app.get('/api/customer',
    function(req, res){             
        const token = req.headers["authorization"].replace("Bearer ", "");
            
        try{
            let decode = jwt.verify(token, SECRET_KEY);               
            if(decode.positionID != 1 && decode.positionID != 2) {
              return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }
            
            let sql = "SELECT * FROM customer";            
            db.query(sql, function (err, result){
                if (err) throw err;            
                res.send(result);
            });      

        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }
        
    }
);


// Profile
app.get('/api/profile/:id',
    async function(req, res){
        const custID = req.params.id;        
        const token = req.headers["authorization"].replace("Bearer ", "");
            
        try{
            let decode = jwt.verify(token, SECRET_KEY);               
            if(custID != decode.custID && decode.positionID != 1 && decode.positionID != 2) {
              return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }
            
            let sql = "SELECT * FROM customer WHERE custID = ? AND isActive = 1";        
            let customer = await query(sql, [custID]);        
            
            customer = customer[0];
            customer['message'] = 'success';
            customer['status'] = true;
            res.send(customer); 

        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }
        
    }
);

// show customer image profile
app.get('/assets/customer/:filename', 
    function(req, res) {        
        const filepath = path.join(__dirname, 'assets/customer', req.params.filename);        
        res.sendFile(filepath);
    }
);

// Update a customer
app.put('/api/customer/:id', 
    async function(req, res){
  
        //Receive a token
        const token = req.headers["authorization"].replace("Bearer ", "");
        const custID = req.params.id;
    
        try{
            //Validate the token    
            let decode = jwt.verify(token, SECRET_KEY);               
            if(custID != decode.custID && decode.positionID != 1 && decode.positionID != 2) {
                return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }
        
            //save file into folder  
            let fileName = "";
            if (req?.files?.imageFile){        
                const imageFile = req.files.imageFile; // image file    
                
                fileName = imageFile.name.split(".");// file name
                fileName = fileName[0] + Date.now() + '.' + fileName[1]; 
        
                const imagePath = path.join(__dirname, 'assets/customer', fileName); //image path
        
                fs.writeFile(imagePath, imageFile.data, (err) => {
                if(err) throw err;
                });
                
            }
    
        
            //save data into database
            const {password, username, firstName, lastName, email, gender } = req.body;
        
            let sql = 'UPDATE customer SET username = ?,firstName = ?, lastName = ?, email = ?, gender = ?';
            let params = [username, firstName, lastName, email, gender];
        
            if (password) {
                const salt = await bcrypt.genSalt(10);
                const password_hash = await bcrypt.hash(password, salt);   
                sql += ', password = ?';
                params.push(password_hash);
            }
        
            if (fileName != "") {    
                sql += ', imageFile = ?';
                params.push(fileName);
            }
        
            sql += ' WHERE custID = ?';
            params.push(custID);
        
            db.query(sql, params, (err, result) => {
                if (err) throw err;
                res.send({ 'message': 'แก้ไขข้อมูลลูกค้าเรียบร้อยแล้ว', 'status': true });
            });
            
        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }    
    }
);
    
// Delete a customer
app.delete('/api/customer/:id',
    async function(req, res){
        const custID = req.params.id;        
        const token = req.headers["authorization"].replace("Bearer ", "");
            
        try{
            let decode = jwt.verify(token, SECRET_KEY);               
            if(custID != decode.custID && decode.positionID != 1 && decode.positionID != 2) {
                return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }
            
            const sql = `DELETE FROM customer WHERE custID = ?`;
            db.query(sql, [custID], (err, result) => {
                if (err) throw err;
                res.send({'message':'ลบข้อมูลลูกค้าเรียบร้อยแล้ว','status':true});
            });

        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }
        
    }
);


/*############## EMPLOYEE ##############*/
//Login (employee/admin)
app.post('/api/admin/login',
    async function(req, res){
        //Validate username
        const {username, password} = req.body;                
        let sql = "SELECT * FROM employee WHERE username=? AND isActive = 1 and positionID = 1";        
        let employee = await query(sql, [username, username]);        
        
        if(employee.length <= 0){            
            return res.send( {'message':'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง','status':false} );
        }else{            
            employee = employee[0];
            empID = employee['empID'];               
            password_hash = employee['password'];       
            positionID = employee['positionID']; 
        }

        //validate a number of attempts 
        let loginAttempt = 0;
        sql = "SELECT loginAttempt FROM employee WHERE username=? AND isActive = 1 ";        
        sql += "AND lastAttemptTime >= CURRENT_TIMESTAMP - INTERVAL 24 HOUR ";        
        
        row = await query(sql, [username, username]);    
        if(row.length > 0){
            loginAttempt = row[0]['loginAttempt'];

            if(loginAttempt>= 3) {
                return res.send( {'message':'บัญชีคุณถูกล๊อก เนื่องจากมีการพยายามเข้าสู่ระบบเกินกำหนด','status':false} );    
            }    
        }else{
            //reset login attempt                
            sql = "UPDATE employee SET loginAttempt = 0, lastAttemptTime=NULL WHERE username=? AND isActive = 1";                    
            await query(sql, [username, username]);               
        }              
        

        //validate password       
        if(bcrypt.compareSync(password, password_hash)){
            //reset login attempt                
            sql = "UPDATE employee SET loginAttempt = 0, lastAttemptTime=NULL WHERE username=? AND isActive = 1";        
            await query(sql, [username, username]);   

            //get token
            const token = jwt.sign({ empID: empID, username: username, positionID: positionID }, 
                                    SECRET_KEY, { expiresIn: '1h' });                

            employee['token'] = token;
            employee['message'] = 'เข้าสู่ระบบสำเร็จ';
            employee['status'] = true;

            res.send(employee);            
        }else{
            //update login attempt
            const lastAttemptTime = new Date();
            sql = "UPDATE employee SET loginAttempt = loginAttempt + 1, lastAttemptTime=? ";
            sql += "WHERE username=? AND isActive = 1";                   
            await query(sql, [lastAttemptTime, username, username]);           
            
            if(loginAttempt >=2){
                res.send( {'message':'บัญชีคุณถูกล๊อก เนื่องจากมีการพยายามเข้าสู่ระบบเกินกำหนด','status':false} );    
            }else{
                res.send( {'message':'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง','status':false} );    
            }            
        }

    }
);

//List employees
app.get('/api/employee',
    function(req, res){             
        const token = req.headers["authorization"].replace("Bearer ", "");
            
        try{
            let decode = jwt.verify(token, SECRET_KEY);               
            if(decode.positionID != 1) {
              return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }
            
            let sql = "SELECT * FROM employee";            
            db.query(sql, function (err, result){
                if (err) throw err;            
                res.send(result);
            });      

        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }
        
    }
);

//Show an employee detail
app.get('/api/employee/:id',
    async function(req, res){
        const empID = req.params.id;        
        const token = req.headers["authorization"].replace("Bearer ", "");
            
        try{
            let decode = jwt.verify(token, SECRET_KEY);               
            if(empID != decode.empID && decode.positionID != 1) {
              return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }
            
            let sql = "SELECT * FROM employee WHERE empID = ? AND isActive = 1";        
            let employee = await query(sql, [empID]);        
            
            employee = employee[0];
            employee['message'] = 'success';
            employee['status'] = true;
            res.send(employee); 

        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }
        
    }
);


//Generate a password
function generateRandomPassword(length) {
    return crypto
        .randomBytes(length)
        .toString('base64')
        .slice(0, length)
        .replace(/\+/g, 'A')  // Replace '+' to avoid special chars if needed
        .replace(/\//g, 'B'); // Replace '/' to avoid special chars if needed
}


//Add an employee
app.post('/api/employee', 
    async function(req, res){
  
        //Receive a token
        const token = req.headers["authorization"].replace("Bearer ", "");        
    
        try{
            //Validate the token    
            let decode = jwt.verify(token, SECRET_KEY);               
            if(decode.positionID != 1) {
                return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }            

            //receive data from users
            const {username, firstName, lastName, email, gender } = req.body;

            //check existing username
            let sql="SELECT * FROM employee WHERE username=?";
            db.query(sql, [username], async function(err, results) {
                if (err) throw err;
                
                if(results.length == 0) {
                    //password and salt are encrypted by hash function (bcrypt)
                    const password = generateRandomPassword(8);
                    const salt = await bcrypt.genSalt(10); //generate salte
                    const password_hash = await bcrypt.hash(password, salt);    
                    
                    //save data into database                
                    let sql = `INSERT INTO employee(
                            username, password, firstName, lastName, email, gender, positionID
                            )VALUES(?, ?, ?, ?, ?, ?, 0)`;   
                    let params = [username, password_hash, firstName, lastName, email, gender];
                
                    db.query(sql, params, (err, result) => {
                        if (err) throw err;
                        res.send({ 'message': 'เพิ่มข้อมูลพนักงานเรียบร้อยแล้ว', 'status': true });
                    });                    

                }else{
                    res.send({'message':'ชื่อผู้ใช้ซ้ำ','status':false});
                }
            });                        
            
        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }    
    }
);
    
//Update an employee
app.put('/api/employee/:id', 
    async function(req, res){
  
        //Receive a token
        const token = req.headers["authorization"].replace("Bearer ", "");
        const empID = req.params.id;
    
        try{
            //Validate the token    
            let decode = jwt.verify(token, SECRET_KEY);               
            if(empID != decode.empID && decode.positionID != 1) {
                return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }
        
            //save file into folder  
            let fileName = "";
            if (req?.files?.imageFile){        
                const imageFile = req.files.imageFile; // image file    
                
                fileName = imageFile.name.split(".");// file name
                fileName = fileName[0] + Date.now() + '.' + fileName[1]; 
        
                const imagePath = path.join(__dirname, 'assets/employee', fileName); //image path
        
                fs.writeFile(imagePath, imageFile.data, (err) => {
                if(err) throw err;
                });
                
            }
            
            //save data into database
            const {password, username, firstName, lastName, email, gender } = req.body;
        
            let sql = 'UPDATE employee SET username = ?,firstName = ?, lastName = ?, email = ?, gender = ?';
            let params = [username, firstName, lastName, email, gender];
        
            if (password) {
                const salt = await bcrypt.genSalt(10);
                const password_hash = await bcrypt.hash(password, salt);   
                sql += ', password = ?';
                params.push(password_hash);
            }
        
            if (fileName != "") {    
                sql += ', imageFile = ?';
                params.push(fileName);
            }
        
            sql += ' WHERE empID = ?';
            params.push(empID);
        
            db.query(sql, params, (err, result) => {
                if (err) throw err;
                res.send({ 'message': 'แก้ไขข้อมูลพนักงานเรียบร้อยแล้ว', 'status': true });
            });
            
        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }    
    }
);
    
// Delete an employee
app.delete('/api/employee/:id',
    async function(req, res){
        const empID = req.params.id;        
        const token = req.headers["authorization"].replace("Bearer ", "");
            
        try{
            let decode = jwt.verify(token, SECRET_KEY);               
            if(decode.positionID != 1) {
                return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }
            
            const sql = `DELETE FROM employee WHERE empID = ?`;
            db.query(sql, [empID], (err, result) => {
                if (err) throw err;
                res.send({'message':'ลบข้อมูลพนักงานเรียบร้อยแล้ว','status':true});
            });

        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }
        
    }
);



/*############## PRODUCT ##############*/
//List products
app.get('/api/product',
    function(req, res){             
        const token = req.headers["authorization"].replace("Bearer ", "");
            
        try{
            let decode = jwt.verify(token, SECRET_KEY);               
            if(decode.positionID != 1 && decode.positionID != 2) {
              return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }
            
            let sql = "SELECT * FROM product";            
            db.query(sql, function (err, result){
                if (err) throw err;            
                res.send(result);
            });      

        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }
        
    }
);

// Get product detail
app.get('/api/product/:id', 
    function (req, res){
        const sql = 'SELECT * FROM product WHERE productID = ?';
        db.query(sql, [req.params.id], (err, result) => {
            if (err) throw err;

            if(result.length > 0) {
                product = result[0];
                product['message'] = 'success';
                product['status'] = true;
                res.json(product);
            }else{
                res.send({'message':'ไม่พบข้อมูลสินค้า','status':false});
            }
        });
    }
);

// show product image
app.get('/assets/product/:filename', 
    function(req, res){
      const filepath = path.join(__dirname, 'assets/product', req.params.filename);  
      res.sendFile(filepath);
    }
);


//Add a product
app.post('/api/product', 
    async function(req, res){
  
        //Receive a token
        const token = req.headers["authorization"].replace("Bearer ", "");        
    
        try{
            //Validate the token    
            let decode = jwt.verify(token, SECRET_KEY);               
            if(decode.positionID != 1 && decode.positionID != 2) {
                return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }
        
            //save file into folder  
            let fileName = "";
            const imageFile = req.files.imageFile; // image file    
            
            fileName = imageFile.name.split(".");// file name
            fileName = fileName[0] + Date.now() + '.' + fileName[1]; 
    
            const imagePath = path.join(__dirname, 'assets/product', fileName); //image path
    
            fs.writeFile(imagePath, imageFile.data, (err) => {
            if(err) throw err;
            });
            
            //save data into database
            const {productName, productDetail, price, cost, quantity, typeID} = req.body;
        
            let sql = `INSERT INTO product(
                       productName, productDetail, price, cost, quantity, imageFile, typeID
                       )VALUES(?, ?, ?, ?, ?, ?, ?)`;                
            let params = [productName, productDetail, price, cost, quantity, fileName, typeID];            
        
            db.query(sql, params, (err, result) => {
                if (err) throw err;
                res.send({ 'message': 'เพิ่มข้อมูลสินค้าเรียบร้อยแล้ว', 'status': true });
            });
            
        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }    
    }
);
    
//Update a product
app.put('/api/product/:id', 
    async function(req, res){
  
        //Receive a token
        const token = req.headers["authorization"].replace("Bearer ", "");
        const productID = req.params.id;
    
        try{
            //Validate the token    
            let decode = jwt.verify(token, SECRET_KEY);               
            if(decode.positionID != 1 && decode.positionID != 2) {
                return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }
        
            //save file into folder  
            let fileName = "";
            if (req?.files?.imageFile){        
                const imageFile = req.files.imageFile; // image file    
                
                fileName = imageFile.name.split(".");// file name
                fileName = fileName[0] + Date.now() + '.' + fileName[1]; 
        
                const imagePath = path.join(__dirname, 'assets/product', fileName); //image path
        
                fs.writeFile(imagePath, imageFile.data, (err) => {
                if(err) throw err;
                });
                
            }
            
            //save data into database
            const {productName, productDetail, price, cost, quantity, typeID} = req.body;
        
            let sql = `UPDATE product SET 
                       productName = ?, productDetail = ?, price = ?, cost = ?, quantity = ?, typeID = ?`;
            let params = [productName, productDetail, price, cost, quantity, typeID];
        
            if (fileName != "") {    
                sql += ', imageFile = ?';
                params.push(fileName);
            }
        
            sql += ' WHERE productID = ?';
            params.push(productID);
        
            db.query(sql, params, (err, result) => {
                if (err) throw err;
                res.send({ 'message': 'แก้ไขข้อมูลสินค้าเรียบร้อยแล้ว', 'status': true });
            });
            
        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }    
    }
);
    
// Delete a product
app.delete('/api/product/:id',
    async function(req, res){
        const productID = req.params.id;        
        const token = req.headers["authorization"].replace("Bearer ", "");
            
        try{
            let decode = jwt.verify(token, SECRET_KEY);               
            if(decode.positionID != 1 && decode.positionID != 2) {
                return res.send( {'message':'คุณไม่ได้รับสิทธิ์ในการเข้าใช้งาน','status':false} );
            }
            
            const sql = 'DELETE FROM product WHERE productID = ?';
            db.query(sql, [productID], (err, result) => {
                if (err) throw err;
                res.send({'message':'ลบข้อมูลสินค้าเรียบร้อยแล้ว','status':true});
            });

        }catch(error){
            res.send( {'message':'โทเคนไม่ถูกต้อง','status':false} );
        }
        
    }
);

app.post('/api/admin/add',async (req,res)=>{
    const {username, password, firstName, lastName, email, gender } = req.body;
 
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password, salt);  
 
    const sql = `INSERT INTO employee(username, password, firstName, lastName, email, gender,positionID
                )VALUES(?, ?, ?, ?, ?, ?, 1)`;            
    db.query(sql, [username, password_hash, firstName, lastName, email, gender], (err) => {
        if (err) throw err;
            res.send({ 'message': 'เพิ่มข้อมูลพนักงานเรียบร้อยแล้ว', 'status': true });
        });                    
})


// Create an HTTPS server
const httpsServer = https.createServer(credentials, app);
app.listen(port, () => {
    console.log(`HTTPS Server running on port ${port}`);
});