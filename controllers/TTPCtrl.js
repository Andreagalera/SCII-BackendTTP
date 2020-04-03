'use strict';
const controllerCtrl = {};

const rsa = require('rsa');
const bc = require('bigint-conversion');
const sha = require('object-sha');

let keyPair;
let k;
let Pko;
let bodyA;
let signatureA;

controllerCtrl.getPublicKeyTTP = async (req, res) => {
  try {
    keyPair = await rsa.generateRandomKeys();
    res.status(200).send({
      e: bc.bigintToHex(keyPair["publicKey"]["e"]),
      n: bc.bigintToHex(keyPair["publicKey"]["n"])
    })
  } catch (err) {
    res.status(500).send({ message: err })
  }
}


controllerCtrl.sendK = async (req, res) => {
  console.log("Recive k");
  console.log(req.body);
  console.log(req.body.k);
  Pko = req.body.signature;
  try {
    k = req.body.body.k;
    var ts = new Date();
    const body = {
      type: "4",
      ttp: "TTP",
      src: "A",
      dest: "B",
      k: k,
      timestamp: ts
    };
    const digest = await sha.digest(body, 'SHA-256');
    const digestHex = bc.hexToBigint(digest);
    const signature = await keyPair["privateKey"].sign(digestHex);
    bodyA = body;
    signatureA = bc.bigintToHex(signature);
    res.status(200).send({
      body: body,
      signature: bc.bigintToHex(signature)
    })
  } catch (err) {
    res.status(500).send({ message: err })
  }

  sendAdvertToB();
}

function sendAdvertToB() {
  require('request')('http://localhost:3000/api/clientes/advertB', (err, res, body) => {
    console.log(body);
  //   try {
  //       res.status(200).send({ message: k})
  // } catch (err) {
  //   res.status(500).send({ message: err })
  // }
  // res.send("Hola");
  }
  )
};

  

  controllerCtrl.downloadK = async (req, res) => {
  console.log("k2", k);
  res.send(k);
}

module.exports = controllerCtrl;