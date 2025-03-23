import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());
  
  // Store the nodes
  const nodes: Node[] = [];

  // Status route
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  // Register node route
  _registry.post("/registerNode", (req: Request<{}, {}, RegisterNodeBody>, res: Response) => {
    const { nodeId, pubKey } = req.body;
    
    // Check if node already exists, update if it does
    const existingNodeIndex = nodes.findIndex(n => n.nodeId === nodeId);
    if (existingNodeIndex !== -1) {
      nodes[existingNodeIndex] = { nodeId, pubKey };
    } else {
      nodes.push({ nodeId, pubKey });
    }
    
    res.send("success");
  });

  // Get node registry route
  _registry.get("/getNodeRegistry", (req, res) => {
    const response: GetNodeRegistryBody = { nodes };
    res.json(response);
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  return server;
}
