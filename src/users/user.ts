import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT, BASE_USER_PORT, REGISTRY_PORT } from "../config";
import { 
  createRandomSymmetricKey, 
  exportSymKey, 
  rsaEncrypt, 
  symEncrypt 
} from "../crypto";
import { GetNodeRegistryBody } from "../registry/registry";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export type MessageBody = {
  message: string;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // Variables to track messages
  let lastSentMessage: string | null = null;
  let lastReceivedMessage: string | null = null;
  let lastCircuit: number[] = [];

  // Status route
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Get last sent message
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // Get last received message
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Get last circuit
  _user.get("/getLastCircuit", (req, res) => {
    res.json({ result: lastCircuit });
  });

  // Receive a message
  _user.post("/message", (req, res) => {
    const { message } = req.body;
    lastReceivedMessage = message;
    res.send("success");
  });

  // Send a message through the onion routing network
  _user.post("/sendMessage", async (req, res) => {
    try {
      const { message, destinationUserId } = req.body;
      
      // Store the sent message
      lastSentMessage = message;
      
      // Get the node registry
      const registryResponse = await fetch(`http://localhost:${REGISTRY_PORT}/getNodeRegistry`);
      const { nodes } = await registryResponse.json() as GetNodeRegistryBody;
      
      if (nodes.length < 3) {
        res.status(400).send("Not enough nodes in the network");
        return; // Add return to end execution for this path
      }
      
      // Create a random circuit of 3 nodes
      const availableNodeIds = nodes.map(node => node.nodeId);
      lastCircuit = [];
      
      // Select 3 random nodes for the circuit
      while (lastCircuit.length < 3 && availableNodeIds.length > 0) {
        const randomIndex = Math.floor(Math.random() * availableNodeIds.length);
        const selectedNodeId = availableNodeIds[randomIndex];
        
        lastCircuit.push(selectedNodeId);
        
        // Remove the selected node to avoid duplicates
        availableNodeIds.splice(randomIndex, 1);
      }
      
      // Get the public keys for the circuit nodes
      const circuitNodes = lastCircuit.map(nodeId => {
        const node = nodes.find(n => n.nodeId === nodeId);
        if (!node) {
          throw new Error(`Node ${nodeId} not found in registry`);
        }
        return {
          nodeId,
          pubKey: node.pubKey,
        };
      });
      
      // Prepare the destination port for the final user
      const finalDestination = `${BASE_USER_PORT + destinationUserId}`.padStart(10, '0');
      
      // Start with the plain message
      let currentMsg = message;
      
      // Apply layers of encryption in reverse order (exit node to entry node)
      for (let i = circuitNodes.length - 1; i >= 0; i--) {
        const node = circuitNodes[i];
        
        // Generate a symmetric key for this layer
        const symKey = await createRandomSymmetricKey();
        const symKeyStr = await exportSymKey(symKey);
        
        // Determine the destination for this layer
        let destination: string;
        if (i === circuitNodes.length - 1) {
          // Exit node -> destination user
          destination = finalDestination;
        } else {
          // Middle or entry node -> next node in circuit
          destination = `${BASE_ONION_ROUTER_PORT + circuitNodes[i + 1].nodeId}`.padStart(10, '0');
        }
        
        // Add the destination prefix to the message
        const messageWithDestination = destination + currentMsg;
        
        // Encrypt the message with the symmetric key
        const encryptedWithSym = await symEncrypt(symKey, messageWithDestination);
        
        // Encrypt the symmetric key with the node's public key
        const encryptedSymKey = await rsaEncrypt(symKeyStr, node.pubKey);
        
        // Combine them for the next layer: RSA(symKey) + AES(destination + message)
        currentMsg = encryptedSymKey + encryptedWithSym;
      }
      
      // Send the final encrypted message to the entry node
      const entryNodeId = lastCircuit[0];
      await fetch(`http://localhost:${BASE_ONION_ROUTER_PORT + entryNodeId}/message`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message: currentMsg,
        }),
      });
      
      res.send("success");
    } catch (error) {
      console.error(`Error sending message from user ${userId}:`, error);
      res.status(500).send("Error sending message");
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
