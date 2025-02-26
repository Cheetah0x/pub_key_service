import { AztecAddress, deriveKeys, Fr, type PXE } from "@aztec/aztec.js";
import { EmailRegistryContract } from "../aztec-contracts/artifacts/EmailRegistry";
import {
  initalisePXE,
  getDefaultFeeOptions,
  getTestAccount,
  fetchGooglePublicKeys,
} from "../utils/helpers";
import RegistryStore from "../utils/registryStore";

export class EmailRegistryService {
  public contract: EmailRegistryContract | null = null;
  private pxe: PXE | null = null;

  async initialize() {
    if (!this.pxe) {
      this.pxe = await initalisePXE();
    }
    return this.pxe;
  }

  async getOrDeployContract() {
    if (!this.pxe) throw new Error("PXE not initialized");

    const registryAddress =
      RegistryStore.getAddress() || process.env.REGISTRY_CONTRACT_ADDRESS;
    const account = await getTestAccount(this.pxe);

    if (!registryAddress) {
      console.log("Deploying new registry contract...");
      const contract = await this.deployContract(account);
      RegistryStore.setAddress(contract.address.toString());
      this.contract = contract;
    } else {
      this.contract = await EmailRegistryContract.at(
        AztecAddress.fromString(registryAddress),
        account
      );
    }

    return this.contract;
  }

  private async deployContract(account: any) {
    if (!this.pxe) throw new Error("PXE not initialized");

    const emailRegistrySecretKey = Fr.random();
    const emailRegistryPublicKeys = (await deriveKeys(emailRegistrySecretKey))
      .publicKeys;
    const paymentOptions = await getDefaultFeeOptions(this.pxe);

    const contract = EmailRegistryContract.deployWithPublicKeys(
      emailRegistryPublicKeys,
      account,
      account.getCompleteAddress().address
    );

    return await contract.send(paymentOptions).deployed();
  }

  public async updateContractJWK_ID(contract: EmailRegistryContract) {
    if (!this.pxe) throw new Error("PXE not initialized");
    if (!contract) throw new Error("Registry address is required");

    const account = await this.getObsidionAccount();
    const hashFields = await fetchGooglePublicKeys();

    // Check each hash and add if not already whitelisted
    for (const hash of hashFields) {
      const isValid = await contract
        .withWallet(account)
        .methods.is_valid_jwk(hash)
        .simulate();

      if (!isValid) {
        await contract.withWallet(account).methods.add_jwk(hash).send();
        // Store the new JWK ID
        RegistryStore.addJwkId(hash.toString());
      }
    }

    // After adding new keys, check and remove old ones
    await this.removeOldJWK_ID(contract);
  }

  private async removeOldJWK_ID(contract: EmailRegistryContract) {
    if (!this.pxe) throw new Error("PXE not initialized");
    if (!contract) throw new Error("Registry address is required");

    const account = await this.getObsidionAccount();
    const currentGoogleKeys = await fetchGooglePublicKeys();
    const storedJwkIds = RegistryStore.getJwkIds();

    // Convert current Google keys to strings for comparison
    const currentKeyStrings = currentGoogleKeys.map(
      (key) => `0x${key.toString()}`
    );

    // Check each stored JWK ID and remove only the outdated ones
    for (const storedJwkId of storedJwkIds) {
      if (!currentKeyStrings.includes(storedJwkId)) {
        const isStillValid = await contract
          .withWallet(account)
          .methods.is_valid_jwk(Fr.fromString(storedJwkId))
          .simulate();

        if (isStillValid) {
          await contract
            .withWallet(account)
            .methods.remove_jwk(Fr.fromString(storedJwkId))
            .send();
          RegistryStore.removeJwkId(storedJwkId); // Remove only this specific JWK ID
        }
      }
    }

    // Add any new keys that aren't already stored
    currentKeyStrings.forEach((key) => {
      if (!storedJwkIds.includes(key as `0x${string}`)) {
        RegistryStore.addJwkId(key as `0x${string}`);
      }
    });
  }

  private async getObsidionAccount() {
    if (!this.pxe) throw new Error("PXE not initialized");
    return await getTestAccount(this.pxe);
  }
}
