import { Router } from "express";
import { emailRegistryController } from "../controllers/googleKeyController";

const router = Router();

router.post("/updateGooglePubKey", emailRegistryController.updateGooglePubKey);

export default router;
