import { hash } from './hash';
import {hmac} from "./hmac";
import {
    randomBytes,
    generateKeyPairSync,
    publicEncrypt,
    privateDecrypt,
    sign,
    verify,
    createSign,
    createVerify
} from "node:crypto";
import {keys} from "./keys";
import {encryptMessage} from "./encryptMessage";
import { generateKeySync } from 'node:crypto'
import {decryptMessage} from "./decryptMessage";

const input: string = "Hello World!";
const salt = randomBytes(32).toString("base64");
const hmacKey = keys.hmac;

/**
 * Hashing examples:
 */
console.log('---------------- Hashing Examples ----------------');
console.log('Hello World Hashed: ', hash(input));
console.log('Hello World Hashed: ',hash(input));
console.log('Hello World Hashed with Salt: ' ,hash(input, salt), '\n');

/**
 * HMAC examples:
 */
console.log('---------------- HMAC Examples ----------------');
console.log(hmac({ input, key: hmacKey }));
console.log(hmac({ input, key: hmacKey }));
console.log(hmac({ input, key: randomBytes(64) }), '\n');

/**
 * Symetric Encryption Examples:
 */
console.log('---------------- Symetric Encryption Examples ----------------');
const message: string = 'This message will be encrypted';
console.log('Original Message: ', message);

const secretKey = generateKeySync('aes', { length: 256 });
const secretKey2 = generateKeySync('aes', { length: 256 });
const initializationVector = randomBytes(16);

const encryptedMessage = encryptMessage({ message, initializationVector, secretKey });
console.log('Encrypted Message: ', encryptedMessage);

const decryptedMessage = decryptMessage({ encryptedMessage, initializationVector, secretKey });
console.log('Decrypted Message: ', decryptedMessage);

/**
 * This will throw an error because the key is different
 */
try {
    const decryptedMessage2 = decryptMessage({ encryptedMessage, initializationVector, secretKey: secretKey2 });
    console.log('Decrypted Message with Different key: ', decryptedMessage2);
} catch (error) {
    console.log('Error decrypting message\n');
}

/**
 * Asymetric Encryption Examples:
 */
console.log('--------------- Asymetric Encryption Examples ----------------');
const messageToEncrypt = 'Message encrypted with public key';
console.log('Message: ', messageToEncrypt);

const { publicKey, privateKey } = generateKeyPairSync('rsa', {  modulusLength: 2048 });

const asymetricEncryptedMessage = publicEncrypt(publicKey, messageToEncrypt);
console.log('Encrypted Message: ', asymetricEncryptedMessage.toString('hex'));

const asymetricDecryptedMessage = privateDecrypt(privateKey, asymetricEncryptedMessage);
console.log('Decrypted Message: ', asymetricDecryptedMessage.toString('utf-8'), "\n");

/**
 * Digital Signature Examples:
 */
console.log('--------------- Digital Signature Examples ----------------');
const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });

const messageToSign = 'Signed message';

console.log('Message: ', messageToSign);

const signer = createSign('SHA256');

const signature = signer.update(messageToSign, 'utf-8').sign(keyPair.privateKey, 'hex');

console.log('Signature: ', signature);

const verifier = createVerify('SHA256');
const isValid = verifier.update(messageToSign, 'utf-8').verify(keyPair.publicKey, signature, 'hex');

const verifier2 = createVerify('SHA256');
const isValid2 = verifier2.update('Dummy Text', 'utf-8').verify(keyPair.publicKey, signature, 'hex');

console.log('Is valid: ', isValid);
console.log('Is valid 2: ', isValid2);




