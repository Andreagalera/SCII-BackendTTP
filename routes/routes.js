const { Router} = require('express');
const router = Router();


const controller = require('../controllers/TTPCtrl');

router.get('/', controller.getData);
router.post('/', controller.postData);
router.post('/sign', controller.signMessage);

module.exports = router;