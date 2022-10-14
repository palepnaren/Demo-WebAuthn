const express  = require('express');
const router   = express.Router();
const keys = require('../businessLogic/pub-key');
const base64ToBuffer = require('base64-arraybuffer');

/* Returns if user is logged in */
router.post('/login', (request, response) => {
    var authenticators;

    keys.getServerAssertion(authenticators, request.session.id, request.session.challenge, function(res){
        console.log("request.session.id inside /login: "+request.session.id);
        // request.session.challenge = res.challenge;
        response.json({data:res,status:200});
    });

    
})

router.post('/register', (request, response) => {

    if(request.session && request.session.username){
        if(request.session.username == request.body.username){
            response.json({message:'Username already exists', status: 400});
            return;
        } 
    }
    keys.initPubKey(request.body, function(res){
        request.session.challenge = res.challenge;
        request.session.username = res.user.name;
        // request.session.id = res.user.id;
         response.json({data:res, status:200});
     });
    
    
})

router.post('/getPublicKey', (request, response) => {
    let pubKeyRes = {
        publickey: '',
        rawId:'',
        type:''
    }
    keys.getPublicKey(request.body, request.session.challenge, function(res){
        request.session.pubKey = res.data.authnrData.get('credentialPublicKeyPem');
        pubKeyRes.publickey = res.data.authnrData.get('credentialPublicKeyPem');
        pubKeyRes.rawId = base64ToBuffer.encode(res.data.clientData.get('rawId'));
        pubKeyRes.type = res.data.request.type;
        pubKeyRes.credId = base64ToBuffer.encode(res.credId);
        request.session.id = pubKeyRes.credId;
        console.log("credId inside /getPubKey: " +request.session.id);
        response.send({data:pubKeyRes,status:200});
    })
    
})

router.post('/validateCreds', (request, response) => {
    keys.valiate(request.body,request.session.pubKey, request.session.challenge, function(res){
        response.json({data: res, status:200});
    });
    

})

module.exports = router;
