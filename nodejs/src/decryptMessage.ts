import {BinaryLike, CipherKey, createCipheriv, createDecipheriv, randomBytes} from "node:crypto";

interface DecryptMessageInput {
    encryptedMessage: string;
    initializationVector: BinaryLike;
    secretKey: CipherKey;
}

export const decryptMessage = ({ encryptedMessage, secretKey, initializationVector }: DecryptMessageInput) => {
    const decipher = createDecipheriv('aes256', secretKey, initializationVector);

    const result = decipher.update(encryptedMessage, 'hex', 'utf-8') + decipher.final('utf8');

    return result.toString();
}
