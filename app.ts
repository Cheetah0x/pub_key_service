import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cron from "node-cron";
import googlePubKeyRouter from "./src/routes/googlePubKey";
import { EmailRegistryService } from "./src/services/EmailRegistryService";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use("/api", googlePubKeyRouter);

// Initialize the service for scheduled updates
const emailRegistryService = new EmailRegistryService();
let isInitialized = false;

const updateGoogleKeys = async () => {
  try {
    if (!isInitialized) {
      await emailRegistryService.initialize();
      await emailRegistryService.getOrDeployContract();
      isInitialized = true;
    }
    await emailRegistryService.updateContractJWK_ID(
      emailRegistryService.contract!
    );
    console.log("Scheduled Google keys update completed");
  } catch (error) {
    console.error("Error updating Google keys:", error);
  }
};

// Schedule updates to run every hour
cron.schedule("0 * * * *", updateGoogleKeys);

// Run initial update when server starts
updateGoogleKeys();

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

export default app;
