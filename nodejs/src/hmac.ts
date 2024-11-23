import { BinaryLike, createHmac } from 'node:crypto'

interface HmacInput {
    input: string;
    key: BinaryLike;
}

export const hmac = ({  input, key }: HmacInput) =>
    createHmac('sha256', key).update(input).digest('hex');
