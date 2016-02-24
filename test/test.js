

var fs = require('fs');
console.log(__dirname + '/../');

var opensslCA = require( __dirname + '/../');
var d = Date.now();
var ca = opensslCA.createCA();
ca.generatePrivateKey( 2084 ) ;
ca.loadCA( fs.readFileSync( __dirname + '/ca.key' ) , fs.readFileSync( __dirname + '/ca.crt' ));

console.log( "take: " + (Date.now() -d) + "ms");

var d = Date.now();
var count = 0;

var host = "7e596f96907b3cc34805-6c8665affa63d6a811287d47acd8acd1.ssl.cf3.rackcdn.com";
 host ="*.com";
ca.createCertificate({
		"serial": Math.floor(Math.random()*0xfffffff) ,"startDate" :new Date(2010,1,1) ,"days": 300 , subjectAltName: "DNS:*.googleapis.com, DNS:googleapis.com", 
		"subject": {  "CN" : host , "C" :"IL" , "O": "FILTER"  , "OU": "FILTER" } 
},function(err,cert){
	console.log(err);
	console.log(cert);
	fs.writeFileSync('t.crt', cert);
	console.log("take: "+  (Date.now() -d) + "ms");
});


