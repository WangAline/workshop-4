import bodyParser from "body-parser";
import express from "express";
import { BASE_USER_PORT } from "../config";

export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());


  // TODO implement the status route
  // Initialisez les placeholders pour les données des messages
  let lastReceivedMessage: string | null = null;
  let lastSentMessage: string | null = null;

  // Implémentez la route /status
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Route pour le dernier message reçu
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Route pour le dernier message envoyé
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // _user.get("/status", (req, res) => {});
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  _user.post("/message", (req, res) => {
    const { message } = req.body; 
    lastReceivedMessage = message; 
    res.status(200).send("success"); 
  });
  
  

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
      `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
