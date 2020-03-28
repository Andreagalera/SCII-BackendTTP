'use strict';
const controllerCtrl = {};

const rsa = require('rsa');
const bc = require('bigint-conversion');
const sha = require('object-sha');

let keyPair;
let k;

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
    res.status(200).send({
      body: body,
      signature: bc.bigintToHex(signature)
    })
  } catch (err) {
    res.status(500).send({ message: err })
  }
}

  controllerCtrl.downloadK = async (req, res) => {
  try {
        res.status(200).send({k})
  } catch (err) {
    res.status(500).send({ message: err })
  }
}

module.exports = controllerCtrl;