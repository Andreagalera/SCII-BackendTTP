const { Router} = require('express');
const router = Router();


const controller = require('../controllers/TTPCtrl');

router.get('/publicKeyTTP', controller.getPublicKeyTTP);
router.post('/msg3', controller.sendK);
router.get('/downloadK', controller.downloadK);


module.exports = router;