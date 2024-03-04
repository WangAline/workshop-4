import bodyParser from "body-parser";
import express from "express";
import { BASE_ONION_ROUTER_PORT} from "../config";
import * as crypto from "../crypto";

export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  // Initialize the placeholders for message data
  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;
  
  const { publicKey, privateKey } = await crypto.generateRsaKeyPair();
  let PriK=await crypto.exportPrvKey(privateKey)
  let PubK=await crypto.exportPubKey(publicKey)
  
  // Route for the last received encrypted message
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  // Route for the last received decrypted message
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  // Route for the last message destination
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });

  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  onionRouter.get('/getPrivateKey', (req, res) => {
    res.json({ result: PriK }); 
  });
  
  await fetch(`http://localhost:8080/registerNode`, {
    method: "POST",
    headers: { "Content-Type": "application/json"},
    body: JSON.stringify({
      nodeId: nodeId,
      pubKey: PubK,
    })
  });


  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
      `Onion router ${nodeId} is listening on port ${
        BASE_ONION_ROUTER_PORT + nodeId
      }`
    );
  });

  return server;
}
