class RegistryStore {
  private static contractAddress: string | null = null;
  private static jwkIds: Set<`0x${string}`> = new Set();

  static setAddress(address: string) {
    this.contractAddress = address;
  }

  static getAddress(): string | null {
    return this.contractAddress;
  }

  static addJwkId(jwkId: `0x${string}`) {
    this.jwkIds.add(jwkId);
  }

  static getJwkIds(): `0x${string}`[] {
    return Array.from(this.jwkIds);
  }

  static removeJwkId(jwkId: `0x${string}`) {
    this.jwkIds.delete(jwkId);
  }
}

export default RegistryStore;
