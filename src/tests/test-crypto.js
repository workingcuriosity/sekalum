const { encrypt, decrypt } = require('../utils/crypto');

const original = JSON.stringify({
    hello: 'world',
    value: 12345
});

const encrypted = encrypt(original);

console.log('Encrypted:');
console.log(encrypted);

const decrypted = decrypt(encrypted);

console.log('\nDecrypted:');
console.log(decrypted);

console.log('\nMatch:', original === decrypted);
