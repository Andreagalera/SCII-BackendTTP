'use strict';
const controllerCtrl = {};

const rsa = require('rsa');
const bc = require('bigint-conversion');
const sha = require('object-sha');

let keyPair;
let k;
let iv;
let Pko;
let bodyA;
let signatureA;
let aPubKey;

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
  console.log(req.body.body.k);
  Pko = req.body.signature;
  aPubKey = new rsa.PublicKey(bc.hexToBigint(req.body.pubKey.e), bc.hexToBigint(req.body.pubKey.n));
  let proofDigest = bc.bigintToHex(await aPubKey.verify(bc.hexToBigint(req.body.signature)));
  let bodyDigest = await sha.digest(req.body.body);
  // Comprovar timestamp
  var tsTTP = new Date();
  var tsA = req.body.body.timestamp;
  tsA = new Date(tsA);
  var seconds = (tsTTP.getTime() - tsA.getTime()) / 1000;
  console.log(seconds);
  if ((bodyDigest === proofDigest) && (seconds < 1)) {
    try {
      k = req.body.body.k;
      iv = req.body.body.iv;
      const body = {
        type: "4",
        ttp: "TTP",
        src: "A",
        dest: "B",
        k: k,
        iv: iv,
        timestamp: tsTTP
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
  else { console.log("Pruebas malamente"); }

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
  res.send(k+"-"+iv);
}

module.exports = controllerCtrl;