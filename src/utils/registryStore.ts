class RegistryStore {
  private static contractAddress: string | null = null;

  static setAddress(address: string) {
    this.contractAddress = address;
  }

  static getAddress(): string | null {
    return this.contractAddress;
  }
}

export default RegistryStore;
