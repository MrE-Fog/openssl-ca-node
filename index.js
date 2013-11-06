

var addon = require('./build/Release/ca');

module.exports.createCA = function(){
    return new addon.CA();
};


