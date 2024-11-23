import {BinaryLike, CipherKey, createCipheriv, randomBytes} from "node:crypto";

interface EncryptMessageInput {
    message: string;
    initializationVector: BinaryLike;
    secretKey: CipherKey;
}

export const encryptMessage = ({ message, secretKey, initializationVector }: EncryptMessageInput) => {
    /**
     * The cipher is the algorithm that will be responsible for the data encryption
     */
    const cipher = createCipheriv('aes256', secretKey, initializationVector);

    return cipher.update(message, 'utf8', 'hex') + cipher.final('hex');
}
