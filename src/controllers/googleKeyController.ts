import { AztecAddress, deriveKeys, Fr, type PXE } from "@aztec/aztec.js";
import type { Request, Response } from "express";
import dotenv from "dotenv";
import {
  getDefaultFeeOptions,
  getTestAccount,
  fetchGooglePublicKeys,
} from "../utils/helpers";
import { initalisePXE } from "../utils/helpers";
import { EmailRegistryContract } from "../aztec-contracts/artifacts/EmailRegistry";
import { PublicKeyRegistry } from "../utils/PublicKeyRegistry";
import RegistryStore from "../utils/registryStore";
import { EmailRegistryService } from "../services/EmailRegistryService";

dotenv.config();

export class EmailRegistryController {
  private service: EmailRegistryService;

  constructor() {
    this.service = new EmailRegistryService();
  }

  updateGooglePubKey = async (req: Request, res: Response): Promise<void> => {
    try {
      await this.service.initialize();
      await this.service.getOrDeployContract();
      const contractAddress = await this.service.updateGoogleKeys();

      res.status(200).json({
        message: "Public keys updated successfully",
        contractAddress,
      });
    } catch (error) {
      console.error("Error:", error);
      res.status(500).json({
        error: "Transaction failed",
        details: error instanceof Error ? error.message : "Unknown error",
      });
    }
  };
}

export const emailRegistryController = new EmailRegistryController();

// export const deployRegistryContract = async (pxe: PXE) => {
//   try {
//     const account = await getObsidionAccount(pxe);

//     //deploy the email registry contract
//     let emailRegistrySecretKey = Fr.random();
//     let emailRegistryPublicKeys = (await deriveKeys(emailRegistrySecretKey))
//       .publicKeys;

//     let paymentOptions = await getDefaultFeeOptions(pxe);

//     let emailRegistryContract = EmailRegistryContract.deployWithPublicKeys(
//       emailRegistryPublicKeys,
//       account,
//       account.getCompleteAddress().address
//     );

//     const emailRegistryContractInstance = await emailRegistryContract
//       .send(paymentOptions)
//       .deployed();

//     return emailRegistryContractInstance;
//   } catch (error) {
//     console.error("Error:", error);
//     throw error;
//   }
// };

// export const updateContractPublicKeys = async (
//   pxe: PXE,
//   registryContract: EmailRegistryContract
// ) => {
//   //make sure the address has been passed in
//   if (!registryContract) {
//     throw new Error("Registry address is required");
//   }

//   try {
//     const account = await getObsidionAccount(pxe);
//     const { hashFields, kids } = await fetchGooglePublicKeys();

//     //query the contract for the public keys
//     const contractGooglePublicKeys = await registryContract
//       .withWallet(account)
//       .methods.get_google_public_key_hashs()
//       .simulate();

//     //check if the keys are the same
//     if (
//       JSON.stringify(contractGooglePublicKeys) !== JSON.stringify(hashFields)
//     ) {
//       //update the keys
//       const updateKeys = await registryContract
//         .withWallet(account)
//         .methods.update_google_public_key_hashs({ hash: hashFields })
//         .send();
//     }
//   } catch (error) {
//     console.error("Error:", error);
//     throw error;
//   }
// };

// //TODO: Make it an account that we contorl
// //will make the MVP with the test accounts first
// export const getObsidionAccount = async (pxe: PXE) => {
//   const account = await getTestAccount(pxe);
//   return account;
// };
