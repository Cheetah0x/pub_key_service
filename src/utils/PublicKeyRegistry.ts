import {
  bnToLimbStrArray,
  bnToRedcLimbStrArray,
} from "@mach-34/noir-bignum-paramgen";
import { utils } from "@shield-labs/utils";
import { decodeJwt } from "./registryUtils.js";
import ky from "ky";
import { Base64, Bytes, Hash, Hex } from "ox";
import { z } from "zod";
import { poseidon2Hash } from "@zkpassport/poseidon2";

// Define JWT header type
type JWTHeader = {
  kid: string;
  n: string;
  e: string;
};

export type PublicKey = {
  kid: string;
  n: string;
  e: string;
  limbs: {
    public_key_limbs: string[];
    public_key_redc_limbs: string[];
  };
  hash: `0x${string}`;
  jwk_id?: `0x${string}`;
};

export class PublicKeyRegistry {
  constructor() {}

  async getPublicKeyByJwt(jwt: string) {
    const decoded = decodeJwt(jwt) as { header: { kid: string } };
    const publicKeys = await this.getPublicKeys();
    // First find the key by kid
    const key = publicKeys.find((key) => key.kid === decoded.header.kid);
    if (!key) {
      throw new Error("Public key not found for jwt");
    }
    // Then derive the jwk_id from the key's n and e
    const jwk_id = await this.deriveJwkId(
      Base64.toBytes(key.n),
      Base64.toBytes(key.e)
    );
    // Update the key with its jwk_id
    return {
      ...key,
      jwk_id,
    };
  }

  async getPublicKeyByJwkId(jwk_id: string) {
    const keys = await this.getPublicKeys();
    console.log("keys", keys);
    const key = keys.find((key) => key.jwk_id === jwk_id);
    if (!key) {
      throw new Error(`Public key not found for jwk_id ${jwk_id}`);
    }
    return key;
  }

  async deriveJwkId(n: Uint8Array, e: Uint8Array): Promise<string> {
    const publicKey = Bytes.toBigInt(n);
    const eBigInt = Bytes.toBigInt(e);
    const limbs = {
      public_key_limbs: bnToLimbStrArray(publicKey),
      public_key_redc_limbs: bnToRedcLimbStrArray(publicKey),
    };

    // Convert all limbs to bigints and concatenate with e
    const allLimbs: bigint[] = [
      ...limbs.public_key_limbs.map((x) => BigInt(x)),
      ...limbs.public_key_redc_limbs.map((x) => BigInt(x)),
      eBigInt,
    ];

    const hash = await poseidon2Hash(allLimbs);
    return ("0x" + hash.toString(16).padStart(64, "0")) as `0x${string}`;
  }

  async getPublicKeys() {
    const urls = ["https://www.googleapis.com/oauth2/v3/certs"];
    const keys = await Promise.all(
      urls.map(async (url) => this.#getPublicKeysByUrl(url))
    );
    console.log("keys", keys);
    return keys.flat();
  }

  async getPublicKeyHash(
    publicKey: {
      public_key_limbs: string[];
      public_key_redc_limbs: string[];
    },
    e: string
  ): Promise<`0x${string}`> {
    // Convert all limbs to bigints
    const allLimbs: bigint[] = [
      ...publicKey.public_key_limbs.map((x) => BigInt(x)),
      ...publicKey.public_key_redc_limbs.map((x) => BigInt(x)),
      Bytes.toBigInt(Base64.toBytes(e)),
    ];

    const hash = await poseidon2Hash(allLimbs);
    const hexString = ("0x" +
      hash.toString(16).padStart(64, "0")) as `0x${string}`;

    console.log("Resulting hash:", hexString);

    return hexString;
  }

  async #getPublicKeysByUrl(url: string): Promise<PublicKey[]> {
    const res = z
      .object({
        keys: z.array(
          z.object({
            kid: z.string(),
            n: z.string(),
            e: z.string(),
          })
        ),
      })
      .parse(await ky.get(url).json());
    const keys = res.keys.map(async (key) => {
      const publicKey = Bytes.toBigInt(Base64.toBytes(key.n));
      const limbs = {
        public_key_limbs: bnToLimbStrArray(publicKey),
        public_key_redc_limbs: bnToRedcLimbStrArray(publicKey),
      };
      return {
        kid: key.kid,
        n: key.n,
        e: key.e,
        limbs,
        hash: await this.getPublicKeyHash(limbs, key.e),
      } as PublicKey;
    });
    return await Promise.all(keys);
  }

  async processGoogleKey(key: {
    kid: string;
    n: string;
    e: string;
  }): Promise<PublicKey> {
    const nBytes = Base64.toBytes(key.n);
    const eBytes = Base64.toBytes(key.e);
    const nBigInt = Bytes.toBigInt(nBytes);

    const limbs = {
      public_key_limbs: bnToLimbStrArray(nBigInt),
      public_key_redc_limbs: bnToRedcLimbStrArray(nBigInt),
    };

    const jwk_id = (await this.deriveJwkId(nBytes, eBytes)) as `0x${string}`;

    return {
      kid: key.kid,
      n: key.n,
      e: key.e,
      limbs,
      hash: await this.getPublicKeyHash(limbs, key.e),
      jwk_id,
    };
  }
}
