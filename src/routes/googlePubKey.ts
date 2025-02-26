import express from "express";
import { EmailRegistryService } from "../services/EmailRegistryService";
import RegistryStore from "../utils/registryStore";

const router = express.Router();
const emailRegistryService = new EmailRegistryService();

// Initialize the service
let isInitialized = false;
const initializeService = async () => {
  if (!isInitialized) {
    await emailRegistryService.initialize();
    await emailRegistryService.getOrDeployContract();
    isInitialized = true;
  }
};

// Force update Google keys
router.post("/google-keys/update", async (req, res) => {
  try {
    await initializeService();
    await emailRegistryService.updateContractJWK_ID(
      emailRegistryService.contract!
    );
    res.json({ success: true, message: "Google keys updated successfully" });
  } catch (error) {
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

// Get current stored JWK IDs
router.get("/google-keys", async (req, res) => {
  try {
    const jwkIds = RegistryStore.getJwkIds();
    res.json({ success: true, jwkIds });
  } catch (error) {
    res.status(500).json({ success: false, error: (error as Error).message });
  }
});

export default router;
