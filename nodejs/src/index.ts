import { hash } from './hash';
import {hmac} from "./hmac";
import {BinaryLike, randomBytes} from "node:crypto";
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
    // console.error(error)
}
