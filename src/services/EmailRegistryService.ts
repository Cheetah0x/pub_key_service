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
  private pxe: PXE | null = null;
  private contract: EmailRegistryContract | null = null;

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

  private async updateContractPublicKeys(contract: EmailRegistryContract) {
    if (!this.pxe) throw new Error("PXE not initialized");
    if (!contract) throw new Error("Registry address is required");

    const account = await this.getObsidionAccount();
    const { hashFields } = await fetchGooglePublicKeys();

    const contractGooglePublicKeys = await contract
      .withWallet(account)
      .methods.get_google_public_key_hashs()
      .simulate();

    if (
      JSON.stringify(contractGooglePublicKeys) !== JSON.stringify(hashFields)
    ) {
      await contract
        .withWallet(account)
        .methods.update_google_public_key_hashs({ hash: hashFields })
        .send();
    }
  }

  private async getObsidionAccount() {
    if (!this.pxe) throw new Error("PXE not initialized");
    return await getTestAccount(this.pxe);
  }

  async updateGoogleKeys() {
    if (!this.pxe || !this.contract) {
      throw new Error("Service not properly initialized");
    }

    await this.updateContractPublicKeys(this.contract);
    return this.contract.address.toString();
  }
}
