import crypto from 'crypto';

/*
Code from: https://stackoverflow.com/questions/6953286/node-js-encrypting-data-that-needs-to-be-decrypted
*/

const ALGORITHM = {
    /**
     * GCM is an authenticated encryption mode that
     * not only provides confidentiality but also 
     * provides integrity in a secured way
     * */
    BLOCK_CIPHER: 'aes-256-gcm',

    /**
     * 128 bit auth tag is recommended for GCM
     */
    AUTH_TAG_BYTE_LEN: 16,

    /**
     * NIST recommends 96 bits or 12 bytes IV for GCM
     * to promote interoperability, efficiency, and
     * simplicity of design
     */
    IV_BYTE_LEN: 12,

    /**
     * Note: 256 (in algorithm name) is key size. 
     * Block size for AES is always 128
     */
    KEY_BYTE_LEN: 32,

    /**
     * To prevent rainbow table attacks
     * */
    SALT_BYTE_LEN: 16
}

function getIV() {
    return crypto.randomBytes(ALGORITHM.IV_BYTE_LEN);
}

function getRandomKey() {
    return crypto.randomBytes(ALGORITHM.KEY_BYTE_LEN);
}

function getSalt() {
    return crypto.randomBytes(ALGORITHM.SALT_BYTE_LEN);
}

/**
 * 
 * @param {Buffer} password - The password to be used for generating key
 * 
 * To be used when key needs to be generated based on password.
 * The caller of this function has the responsibility to clear 
 * the Buffer after the key generation to prevent the password 
 * from lingering in the memory
 */
function getKeyFromPassword(password, salt) {
    return crypto.scryptSync(password, salt, ALGORITHM.KEY_BYTE_LEN);
}

/**
 * 
 * @param {Buffer} messagetext - The clear text message to be encrypted
 * @param {Buffer} key - The key to be used for encryption
 * 
 * The caller of this function has the responsibility to clear 
 * the Buffer after the encryption to prevent the message text 
 * and the key from lingering in the memory
 */
function _encrypt(message, key) {
    const iv = getIV();
    const cipher = crypto.createCipheriv(
        ALGORITHM.BLOCK_CIPHER, key, iv, { 'authTagLength': ALGORITHM.AUTH_TAG_BYTE_LEN }
    );

    let encrypted = Buffer.concat([cipher.update(message), cipher.final()]);

    return Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
}

/**
 * 
 * @param {Buffer} ciphertext - Cipher text
 * @param {Buffer} key - The key to be used for decryption
 * 
 * The caller of this function has the responsibility to clear 
 * the Buffer after the decryption to prevent the message text 
 * and the key from lingering in the memory
 */
function _decrypt(ciphertext, key) {
    const iv = ciphertext.slice(0, ALGORITHM.IV_BYTE_LEN);
    const authTag = ciphertext.slice(ALGORITHM.IV_BYTE_LEN, ALGORITHM.IV_BYTE_LEN + ALGORITHM.AUTH_TAG_BYTE_LEN);
    const encrypted = ciphertext.slice(ALGORITHM.IV_BYTE_LEN + ALGORITHM.AUTH_TAG_BYTE_LEN);

    const decipher = crypto.createDecipheriv(
        ALGORITHM.BLOCK_CIPHER, key, iv, { 'authTagLength': ALGORITHM.AUTH_TAG_BYTE_LEN }
    );

    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

/**
Implementation functions encrypt() and decrypt().

Parameters:
    encrypt()
        @param {String} plainkey = global key in base64 string format
        @param {String} message = message to be encrypted

    decrypt()
        @param {String} rawplainkey = global key in base64 string format
        @param {String:Base64} rawcipher = encrypted message to be decrypted
**/

function encrypt(plainkey, message) {
    const bufferplainkey = Buffer.from(Buffer.from(plainkey, 'base64').toString('ascii'));
    const salt = getSalt();
    const key = getKeyFromPassword(bufferplainkey, salt);
    // console.log(salt, plainkey, bufferplainkey, key);

    const bffr = _encrypt(message, key);
    const content = bffr.toString('base64');
    const saltstr = salt.toString('base64');

    return { content: saltstr + "$$$" + content, buffer: bffr };
}

function decrypt(plainkey, rawcipher) {
    const bufferplainkey = Buffer.from(Buffer.from(plainkey, 'base64').toString('ascii'));
    const salt = Buffer.from(rawcipher.split("$$$")[0], 'base64');
    const key = getKeyFromPassword(bufferplainkey, salt);
    // console.log(salt, plainkey, bufferplainkey, key);

    const cipher = Buffer.from(rawcipher.split("$$$")[1], 'base64');
    const bffr = _decrypt(cipher, key);
    const content = bffr.toString('utf8');

    return { content, buffer: bffr }
}

/**
    @param {Buffer} bffr - containing the Buffer value

    Clears supplied buffer from memory (untested)
**/
function clearBuffer(bffr) {
    bffr.fill(0);
}

/*
Exports
*/

export default {
    // getIV,
    // getRandomKey,
    // getSalt,
    // getKeyFromPassword,
    // _encrypt,
    // _decrypt,
    encrypt,
    decrypt,
    clearBuffer
}