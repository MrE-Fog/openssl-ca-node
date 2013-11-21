var fs = require("fs");

var req = require("../").createCA();



var pkey = fs.readFileSync(__dirname + "/master_server.key") ;


//req.loadPrivateKey(pkey);
console.log(req.generatePrivateKey(2084));
var capkey = fs.readFileSync(__dirname + "/ca.key") ;
var ca_cert = fs.readFileSync(__dirname + "/ca.crt") ;
console.log(req.loadCA(capkey,ca_cert));


var d = new Date();

var csr = req.createCertificate({"serial": Math.floor(Math.random()*0xffffffff) ,"startDate" :new Date(3) ,"days": 10 , "subject": { "C" :"AU" , "O": "HELLO" } });



// 'world'var addon = require('./build/Release/ca');
console.log("take %d", new Date() - d);
console.log(csr); 

var d = new Date();
//var csr = req.createCertificate( { "C" :"AU" , "O": "HELLO" });
console.log("take %d", new Date() - d);
var d = new Date();
//var csr = req.createCertificate( { "C" :"AU" , "O": "HELLO" });
console.log("take %d", new Date() - d);

fs.writeFileSync("csr.csr",csr);
