import {randomBytes} from "node:crypto";

export const keys = {
    hmac: randomBytes(32)
}
