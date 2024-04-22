import { Buffer } from 'buffer';
import Serializer from 'php-serialize';
const { subtle: Crypto } = globalThis.crypto;

export class Encrypter
{
  /**
   * Cipher key.
   *
   * @var { Buffer }
   */
  protected key: Buffer;

  /**
   * Supported cipher algorithms.
   *
   * @var { Record<string, CipherAlgorithm> }
   */
  public static algorithms: Record<string, CipherAlgorithm> = {
    'aes-128-cbc': {
      algorithm: 'AES-CBC',
      key: { length: 16 },
      iv: { length: 16 },
    },
    'aes-256-cbc': {
      algorithm: 'AES-CBC',
      key: { length: 32 },
      iv: { length: 16 },
    },
    'aes-128-gcm': {
      algorithm: 'AES-GCM',
      key: { length: 16 },
      iv: { length: 12 },
    },
    'aes-256-gcm': {
      algorithm: 'AES-GCM',
      key: { length: 32 },
      iv: { length: 12 },
    },
  }

  /**
   * Encrypter constructor.
   *
   * @param { Buffer } key
   * @param { string } algorithm
   */
  constructor(key: Buffer, protected readonly algorithm: string = 'aes-256-cbc') {
    // Validate algorithm.
    if (!Encrypter.isSupported(algorithm)) {
      throw new Error(`Cipher algorithm [${algorithm}] is not supported.`);
    }

    // Validate cipher key.
    if (key.byteLength !== this.getCipher().key.length) {
      throw new Error('Invalid cipher key');
    }

    // Set cipher key.
    this.key = key;
  }

  /**
   * Encrypt value.
   *
   * @param { string } value
   * @param { boolean } serialize
   * @returns { Promise<string> }
   */
  public encrypt = async (value: string, serialize: boolean = true): Promise<string> => {
    // Current chiper.
    const cipher = this.getCipher();

    // Create cipher key.
    const cipherKey = await this.createCipherKey(['encrypt']);

    // Create cipher IV.
    const iv = this.randomBytes(this.getCipher().iv.length);

    // Serialize value.
    value = serialize ? Serializer.serialize(value) : value;

    // Create value buffer.
    const data = Buffer.from(value);

    // Create encryption payload.
    const payload = cipher.algorithm === 'AES-GCM'
      ? await this.encryptWithGCM(cipher, cipherKey, iv, data)
      : await this.encryptWithCBC(cipher, cipherKey, iv, data);

    return btoa(JSON.stringify(payload));
  }

  /**
   * Encrypt value without serialization.
   *
   * @param { string } value
   * @returns { Promise<string> }
   */
  public encryptString = async (value: string): Promise<string> => {
    return this.encrypt(value, false);
  }

  /**
   * Encrypt with AES-CBC.
   *
   * @param { CipherAlgorithm } cipher
   * @param { CryptoKey } cipherKey
   * @param { Buffer } iv
   * @param { Buffer } data
   * @returns { Promise<Payload> }
   */
  protected encryptWithCBC = async (cipher: CipherAlgorithm, cipherKey: CryptoKey, iv: Buffer, data: Buffer): Promise<Payload> => {
    try {
      // Encrypt value.
      const encryptedData = await Crypto.encrypt({ name: cipher.algorithm, iv: iv }, cipherKey, data);

      // Encode IV and encrypted value.
      const encodedIv = iv.toString('base64');
      const encodedEncryptedData = Buffer.from(encryptedData).toString('base64');

      return {
        iv: encodedIv,
        value: encodedEncryptedData,
        mac: await this.sign(Buffer.from(encodedIv + encodedEncryptedData)).then(signature => Buffer.from(signature).toString('hex')),
      } as Payload;
    } catch {
      throw new Error('Could not encrypt data');
    }
  }

  /**
   * Encrypt with AES-GCM.
   *
   * @param { CipherAlgorithm } cipher
   * @param { CryptoKey } cipherKey
   * @param { Buffer } iv
   * @param { Buffer } data
   * @returns { Promise<Payload> }
   */
  protected encryptWithGCM = async (cipher: CipherAlgorithm, cipherKey: CryptoKey, iv: Buffer, data: Buffer): Promise<Payload> => {
    try {
      // Encrypt value.
      const encryptedData = await Crypto.encrypt({ name: cipher.algorithm, iv: iv, tagLength: 128 }, cipherKey, data);

      // Split value and auth tag.
      const value = encryptedData.slice(0, -16);
      const tag = encryptedData.slice(-16);

      return {
        iv: iv.toString('base64'),
        value: Buffer.from(value).toString('base64'),
        mac: '',
        tag: Buffer.from(tag).toString('base64'),
      } as Payload
    } catch {
      throw new Error('Could not encrypt data');
    }
  }

  /**
   * Decrypt payload.
   *
   * @param { string } payload
   * @param { boolean } unserialize
   * @returns { Promise<string> }
   */
  public decrypt = async (payload: string, unserialize: boolean = true): Promise<string> => {
    // Current chiper.
    const cipher = this.getCipher();

    // Create cipher key.
    const cipherKey = await this.createCipherKey(['decrypt']);

    // Decode encryption payload.
    const decodedPayload = this.decodePayload(payload);

    // Extract IV from decoded payload.
    const iv = Buffer.from(decodedPayload.iv, 'base64');

    // Decrypt data.
    const decryptedData = cipher.algorithm === 'AES-GCM'
      ? await this.decryptWithGCM(cipher, cipherKey, iv, decodedPayload)
      : await this.decryptWithCBC(cipher, cipherKey, iv, decodedPayload);

    // Convert decrypted data to string.
    const value = Buffer.from(decryptedData).toString('utf8');

    // Unserialize value.
    return unserialize ? Serializer.unserialize(value) : value;
  }

  /**
   * Decrypt payload without unserialization.
   *
   * @param { string } payload
   * @returns { Promise<string> }
   */
  public decryptString = async (payload: string): Promise<string> => {
    return this.decrypt(payload, false);
  }

  /**
   * Decrypt with AES-CBC.
   *
   * @param { CipherAlgorithm } cipher
   * @param { CryptoKey } cipherKey
   * @param { Buffer } iv
   * @param { Payload } payload
   * @returns { Promise<ArrayBuffer> }
   */
  protected decryptWithCBC = async (cipher: CipherAlgorithm, cipherKey: CryptoKey, iv: Buffer, payload: Payload): Promise<ArrayBuffer> => {
    try {
      // Verify signature.
      const mac = payload.mac !== '' ? Buffer.from(payload.mac, 'hex') : null
      if (!mac || !this.verify(mac, iv, payload.value)) {
        throw new Error('Could not decrypt data');
      }

      // Decrypt data.
      return await Crypto.decrypt({ name: cipher.algorithm, iv: iv }, cipherKey, Buffer.from(payload.value, 'base64'));
    } catch {
      throw new Error('Could not decrypt data');
    }
  }

  /**
   * Decrypt with AES-GCM.
   *
   * @param { CipherAlgorithm } cipher
   * @param { CryptoKey } cipherKey
   * @param { Buffer } iv
   * @param { Payload } payload
   * @returns { Promise<ArrayBuffer> }
   */
  protected decryptWithGCM = async (cipher: CipherAlgorithm, cipherKey: CryptoKey, iv: Buffer, payload: Payload): Promise<ArrayBuffer> => {
    try {
      // Ensure tag is valid.
      const tag = payload.tag ? Buffer.from(payload.tag, 'base64') : null;
      if (!tag || tag.byteLength !== 16) {
        throw new Error('Could not decrypt data');
      }

      // Decrypt data.
      return await Crypto.decrypt({ name: cipher.algorithm, iv: iv, tagLength: 128 }, cipherKey, Buffer.concat([Buffer.from(payload.value, 'base64'), tag]));
    } catch {
      throw new Error('Could not decrypt data');
    }
  }

  /**
   * Sign value with HMAC.
   *
   * @param { Buffer } value
   * @returns { Promise<ArrayBuffer> }
   */
  protected sign = async (value: Buffer): Promise<ArrayBuffer> => {
    const hmacKey = await this.createHmacKey();
    return Crypto.sign('HMAC', hmacKey, value);
  }

  /**
   * Verify HMAC signature.
   *
   * @param { Buffer } signature
   * @param { Buffer } iv
   * @param { string } value
   * @returns { Promise<boolean> }
   */
  protected verify = async (signature: Buffer, iv: Buffer, value: string): Promise<boolean> => {
    const hmacKey = await this.createHmacKey();
    return Crypto.verify('HMAC', hmacKey, signature, Buffer.from(iv.toString('base64') + value));
  }

  /**
   * Decode encrypted payload.
   *
   * @param { string } encryptedPayload
   * @returns { Payload }
   */
  protected decodePayload = (encryptedPayload: string): Payload => {
    const payload = JSON.parse(Buffer.from(encryptedPayload, 'base64').toString('utf8'));
    if (typeof payload !== 'object') {
      throw new Error('Unexpected payload format');
    }

    ['iv', 'value', 'mac'].forEach(key => {
      if (payload[key] === null || payload[key] === undefined || typeof payload[key] !== 'string') {
        throw new Error('Unexpected payload');
      }
    });

    if (Buffer.from(payload.iv, 'base64').byteLength !== this.getCipher().iv.length) {
      throw new Error('Invalid payload');
    }

    return payload as Payload;
  }

  /**
   * Get current cipher algorithm.
   *
   * @returns { CipherAlgorithm }
   */
  protected getCipher = (): CipherAlgorithm => {
    return Encrypter.algorithms[this.algorithm];
  }

  /**
   * Create cipher key.
   *
   * @returns { Promise<CryptoKey> }
   */
  protected createCipherKey = async (usage: KeyUsage[]): Promise<CryptoKey> => {
    return await Crypto.importKey('raw', this.key, { name: this.getCipher().algorithm }, false, usage);
  }

  /**
   * Create HMAC key.
   *
   * @returns { Promise<CryptoKey> }
   */
  protected createHmacKey = async (): Promise<CryptoKey> => {
    return await Crypto.importKey('raw', this.key, {
      name: 'HMAC',
      hash: 'SHA-256',
    }, false, ['sign', 'verify']);
  }

  /**
   * Get an unsigned 8-bit typed array of random bytes.
   *
   * @param { string } length
   * @returns { Buffer }
   */
  protected randomBytes = (length: number): Buffer => {
    return Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(length)));
  }

  /**
   * Check whether a cipher algorithm is supported or not.
   *
   * @param { string } algorithm
   * @returns { boolean }
   */
  public static isSupported = (algorithm: string): boolean => {
    return Encrypter.algorithms.hasOwnProperty(algorithm.toLowerCase());
  }
}

type CipherAlgorithm = {
  algorithm: string,
  key: {
    length: number
  },
  iv: {
    length: number
  },
}

type Payload = {
  iv: string;
  value: string;
  mac: string;
  tag?: string;
}
