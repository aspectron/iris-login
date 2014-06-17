var fs = require('fs');
var path = require('path');

eval(fs.readFileSync(path.join(__dirname,'http/js-scrypt/browser/scrypt.js'), { encoding : 'utf8' }));
var scrypt = scrypt_module_factory();
scrypt.encode = scrypt.crypto_scrypt;
module.exports = scrypt;