import {
  createPXEClient,
  GrumpkinScalar,
  NoFeePaymentMethod,
} from "@aztec/aztec.js";
import { AccountManager } from "@aztec/aztec.js";
import { SingleKeyAccountContract } from "@aztec/accounts/single_key";
import { deriveMasterIncomingViewingSecretKey, Fr } from "@aztec/aztec.js";
import type { PXE, SendMethodOptions } from "@aztec/aztec.js";
import { getSchnorrAccount } from "@aztec/accounts/schnorr";
import { getDeployedTestAccountsWallets } from "@aztec/accounts/testing";
import dotenv from "dotenv";
import { GasSettings } from "@aztec/circuits.js";
import { PublicKeyRegistry } from "./PublicKeyRegistry";

dotenv.config();

export const initalisePXE = async () => {
  const pxe = createPXEClient(
    process.env.SANDBOX_URL || "http://localhost:8080"
  );
  return pxe;
};

export const createAccount = async (pxe: PXE) => {
  // Generate a new secret key for each wallet
  const secretKey = Fr.random();
  const encryptionPrivateKey = deriveMasterIncomingViewingSecretKey(secretKey);
  const accountContract = new SingleKeyAccountContract(encryptionPrivateKey);

  // Create a new AccountManager instance
  const account = await AccountManager.create(pxe, secretKey, accountContract);

  // Register the account and get the wallet
  const wallet = await account.register(); // Returns AccountWalletWithSecretKey

  console.log("registered account");
  return { wallet, secretKey };
};

export const createSchnorrAccount = async (pxe: PXE) => {
  const secretKey = Fr.random();
  const signingPrivateKey = GrumpkinScalar.random();
  const wallet = (
    await getSchnorrAccount(pxe, secretKey, signingPrivateKey)
  ).waitSetup();

  return { wallet, secretKey };
};

export const getTestAccount = async (pxe: PXE) => {
  const accs = await getDeployedTestAccountsWallets(pxe);
  return accs[0];
};

export const getDefaultFeeOptions = async (
  pxe: PXE
): Promise<SendMethodOptions> => {
  const fees = await pxe.getCurrentBaseFees();
  const gasSettings = GasSettings.default({
    maxFeesPerGas: fees,
  });
  const paymentMethod = new NoFeePaymentMethod();
  return {
    fee: { gasSettings, paymentMethod },
  };
};

export interface GooglePublicKey {
  hashFields: Fr[];
  kids: string[];
}

export async function fetchGooglePublicKeys(): Promise<GooglePublicKey> {
  const publicKeyRegistry = new PublicKeyRegistry();
  const response = await fetch("https://www.googleapis.com/oauth2/v3/certs");
  const { keys } = await response.json();

  const firstkey = keys[0];
  const secondkey = keys[1];

  const firstPublicKey = await publicKeyRegistry.getPublicKeyByKid(
    firstkey.kid
  );
  const secondPublicKey = await publicKeyRegistry.getPublicKeyByKid(
    secondkey.kid
  );

  return {
    hashFields: [
      Fr.fromString(firstPublicKey.hash),
      Fr.fromString(secondPublicKey.hash),
    ],
    kids: [firstkey.kid, secondkey.kid],
  };
}
