

var addon = require('./build/Release/ca');

module.exports = addon.CA;

module.exports.createCA = function(){
    return new addon.CA();
};


