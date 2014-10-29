

var fs = require('fs');
console.log(__dirname + '/../');

var opensslCA = require( __dirname + '/../');
var d = Date.now();
var ca = opensslCA.createCA();
ca.generatePrivateKey( 2084 ) ;
ca.loadCA( fs.readFileSync( __dirname + '/ca/ca.key' ) , fs.readFileSync( __dirname + '/ca/ca.crt' ));

console.log( "take: " + (Date.now() -d) + "ms");

var d = Date.now();
var count = 0;


ca.createCertificate({
		"serial": Math.floor(Math.random()*0xfffffff) ,"startDate" :new Date(2010,1,1) ,"days": 300 , 
		"subject": {  "CN" : "test.com" , "C" :"IL" , "O": "FILTER"  , "OU": "FILTER" } 
},function(err,cert){
	console.log(err);
	console.log(cert);
	console.log("take: "+  (Date.now() -d) + "ms");
});


