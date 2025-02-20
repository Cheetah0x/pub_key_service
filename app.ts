import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import googlePubKeyRouter from "./src/routes/googlePubKey";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());
app.use("/api", googlePubKeyRouter);

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

export default app;
