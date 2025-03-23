import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import { 
  exportPrvKey, 
  exportPubKey, 
  generateRsaKeyPair, 
  importPrvKey, 
  rsaDecrypt,
  symDecrypt
} from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // Generate key pair for this node
  const { publicKey, privateKey } = await generateRsaKeyPair();
  const pubKeyString = await exportPubKey(publicKey);
  const prvKeyString = await exportPrvKey(privateKey);

  // Variables to track last message
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;

  // Status route
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  // Get private key route
  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: prvKeyString });
  });

  // Get last received encrypted message
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  // Get last received decrypted message
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  // Get last message destination
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  // Message route - process onion routing message
  onionRouter.post("/message", async (req, res) => {
    try {
      const { message } = req.body;
      
      // Store the encrypted message
      lastReceivedEncryptedMessage = message;
      
      // According to the utils.js file in tests, the message is parsed like this:
      // First 344 chars (0x158 in hex) are the RSA-encrypted symmetric key
      const rsaEncryptedSymKey = message.slice(0, 344);
      const ciphertext = message.slice(344);
      
      // Step 1: Decrypt the symmetric key using the node's private key
      const importedPrivateKey = await importPrvKey(prvKeyString!);
      const symKey = await rsaDecrypt(rsaEncryptedSymKey, importedPrivateKey);
      
      // Step 2: Decrypt the ciphertext using the symmetric key
      const decryptedData = await symDecrypt(symKey, ciphertext);
      
      // Store the decrypted message
      lastReceivedDecryptedMessage = decryptedData;
      
      // Extract the destination and the next layer of the message
      // The first 10 characters of the decrypted message indicate the next destination
      const nextDestinationStr = decryptedData.slice(0, 10);
      const nextMessage = decryptedData.slice(10);
      
      // Parse the destination port
      const nextDestination = parseInt(nextDestinationStr);
      lastMessageDestination = nextDestination;
      
      // Forward the message to the next destination
      await fetch(`http://localhost:${nextDestination}/message`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: nextMessage,
        }),
      });
      
      res.send("success");
    } catch (error) {
      console.error(`Error processing message at node ${nodeId}:`, error);
      res.status(500).send("Error processing message");
    }
  });

  // Register this node with the registry upon startup
  try {
    await fetch(`http://localhost:${REGISTRY_PORT}/registerNode`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        nodeId,
        pubKey: pubKeyString,
      }),
    });
    console.log(`Node ${nodeId} registered successfully`);
  } catch (error) {
    console.error(`Failed to register node ${nodeId}:`, error);
  }

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
