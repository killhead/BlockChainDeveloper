let elliptic = require('elliptic');
const crypto = require('crypto');
const secp256k1 = require('secp256k1');
let ec = new elliptic.ec('secp256k1');

const msg = process.argv[2];
const digested = digest(msg);
console.log(`0) Alice's message:
	message: ${msg}
	message digest: ${digested.toString("hex")}`);

// generate privateKey
let privateKey;
do {
  privateKey = crypto.randomBytes(32);
  console.log("try: "+ privateKey);
} while (!secp256k1.privateKeyVerify(privateKey));
// get the public key in a compressed format
const publicKey = secp256k1.publicKeyCreate(privateKey);
console.log(`1) Alice aquired new keypair:
	publicKey: ${publicKey.toString("hex")}
	privateKey: ${privateKey.toString("hex")}`);

console.log(`2) Alice signed her message digest with her privateKey to get its signature:`);

const signature = ec.sign(digested, privateKey,"hex", {canonical: true});
console.log("   Signature:", signature);

console.log(`3) Bob verified by 3 elements ("message digest", "signature", and Alice's "publicKey"):`);
let verified = ec.verify(digested, signature, publicKey);
console.log("   verified:", verified);

// let test_verified = ec.verify("test", signature, publicKey);
// console.log("   broken message verified: ", test_verified)

function digest(str, algo = "sha256") {
  return crypto.createHash('md5').update('Apple').digest("hex");
}
