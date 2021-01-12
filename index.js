const http = require('http'); 
const express = require('express'); 
const app = express(); 
 
const bodyParser = require('body-parser');
app.use(bodyParser.json());

//const jwt = require('jsonwebtoken');
require("dotenv-safe").config();
const fs = require('fs'); 

//*********************************
var jose = require('node-jose');
const {JWE} = require("node-jose");
const {JWK} = require("node-jose");
const {JWS} = require("node-jose");
const {util} = require("node-jose");

app.get('/', (req, res, next) => {
    
    res.json({message: "Tudo ok por aqui!"});
})
 
app.get('/clientes', (req, res, next) => { 
    console.log(process.env.SECRET);
    res.json([{id:1,nome:'luiz'}]);
}) 

app.get('/read-file', async (req, res) =>  {
    var input = null;
    fs.readFileSync('sender-jwkset.json', 'utf8', (err, jsonString) => {
        if (err) {
            console.log("File read failed:", err)
            return
        }

        input = jsonString;
    });

    var privateKey = fs.readFileSync('sender-jwkset.json');
    var token = jwt.sign({ id }, privateKey, { algorithm: 'RS256' }, function(err, token) {
        console.log(token);
    });
});

app.get('/encrypt-0', async (req, res) =>  {

    const id = 1; //esse id viria do banco de dados

    var input = {
        "keys": [
          {
            "kty": "RSA",
            "d": "ObwizyeOJQW7EUINYaphJ2l1o-jgBjlqo85U-w8488PhmWRVzUjMUEp8B0LdhReRuyJm91H64thHiXLwSs9CMDxVtLQQOmTU7_dFFHrvC0PSOzMuvPg745OFzuNgGA_IMZwQqkT3xyfF5CUfi1ipdRRY_LxydrZ6WX-FcDnFqgvhpnQ0Yxh51C3qnMDtTPfJTMx0Aj7hcOLoAIPA5bcfDDx35tN_AJvXygKXR3KbJzTPRjhFLx0_n8J_P5ApG-cBxWtrAg3lQg7i5HWTOemLWaH2G_gL9KBzyb4GYbhYa7bNr49IRecKt2AULIiWB_jF0odA14NSL6pe4ribAtevwQ",
            "e": "AQAB",
            "use": "sig",
            "kid": "1",
            "n": "qcJ3jkZgAJiHPdD2eayrtKOoRECvfOXzCRK96sESN0E4AaFTziMMkO7bGB5I4ut2QEwansNkuceWcfzH9ZypeVmkv41iszVvLVvK42PKu4uCJ12SULstZmLn6259e-R71FuuKIQ-kwgzf_6SfcS4nV80Nsd-Y1w6qucNg_h8uvZC3xVAYpeotjWEr2FxMAnaDfm0sNX8to78UhJqzrLJRfCLPqzaPgs6Afsjy49w5Clgh6Fb_nonLKkAKjBJkN_3596VIFF7h3uuSWC6ho8xbOEbN69XB1PwQYWyJU_Q-47ewG4VtrKfJDi338uMXWNMLRBrCtCplwdIv86pa_56wQ"
          }
        ]
    };
    console.log("webkey", input);
    
    jose.JWK.asKeyStore(input)
    .then(function(result) {
    
        var keystore = JSON.stringify(result.toJSON(true));

        console.log('keystore:',keystore);

        const encryptionKey = result.get(input.keys[0].kid);
        const output = jose.util.base64url.encode("Hello World");
        const output2 = jose.util.asBuffer(output);

        //encrypting content
        jose.JWE.createEncrypt(encryptionKey)
        .update(output2)
        .final()
        .then((jweInGeneralSerialization) => {
            console.log("Encryption result", JSON.stringify(jweInGeneralSerialization));
        }, (error) => {
            console.log("error2", error.message);
        });
        
    }, (error) => {
        console.log("error1", error.message);
    });

    return res.json({ auth: 'encrypt-0' });
});

app.get('/encrypt-1', async (req, res) =>  {

    const id = 1;
    var contentAlg = "A256CBC-HS512";
    var store = JWK.createKeyStore();

    //Generate a local private key. 
    await store.generate("RSA",2048,{alg:"RS256", key_ops:["sign", "decrypt", "unwrap"]});
    lkey = (await store.get());
    JSON.stringify(lkey.toJSON(true))

    //Assign key properties useful in the encryption/decryption process:
    var key = lkey.toJSON();
    key.use = "verify";
    key.key_ops=["encrypt","verify", "wrap"];
    
    //Make the JSON public key in to a JWK and Store in the KeyStore:
    var pubKey = await JWK.asKey(key);
    await store.add(pubKey);
    JSON.stringify(pubKey.toJSON());
    console.log(key);

    //Release local variables after their usage scope has passed.
    key = null;
    pubkey = null;

    //Set Token Playload:
    var dt = new Date();
    var exp = new Date(dt.getTime() + (20 * 60 * 1000));

    var payload = 
    {
    "nameid":"240820080175",
    "activityid":"a8f769d0-a129-4ad0-8fe9-5bc7761d0331",
    "authmethod":"ATN",
    "decision":"5556",
    "month":"11",
    "day":"19",
    "year":"1982",
    "role":"User",
    "nbf":Math.floor((dt.getTime() / 1000)),
    "exp":Math.floor(exp.getTime() / 1000),
    "iat":Math.floor((dt.getTime() / 1000)),
    "iss":"http://localhost:50191",
    "aud":"http://localhost:50191"
    };

    //Sign the payload; generate the first token:
    var token = await JWS.createSign({format: 'compact'}, lkey).update(JSON.stringify(payload), "utf8").final();


    //Get the server/recipient public Key:
    skey = await JWK.asKey(
    {"kid":"qQ1hDBdtvgbtXziPRmT09XS-6oc3vugIvkHdd8Kh1rk","kty":"RSA","key_ops":["encrypt","verify","wrapKey"],"n":"vuxR5sMnOz8LUCx-8zO6MexL8s_VA1t8FIh4_eUFgebQkyCvxHvQjTtHsqExWg_rJH_qyo3_EXK5lZXbRDbXN8TTwsDs79SrDqf3NoLLSMjGe3fS97HObP1WEcy0mFUDDlvz8Cdq0jXLnrvLKx5G_Pfz52NoGa3R5Gp8KrljeOqkd0DuV5qPtPc-EBkRhjnjH_IVsBeZ3gYGW8m6GqnREtK0lHvBTcdTUgQZZUHHzbpTv6Ta1ZQbImzDCuWBzlHQqbf8Zr6hb75rYTvfpS0NHD7WOjJBQn0PPxS0FSbZOd7ns3ZwbxAfzOwi7IoIGOl62GFxmowwnRAuJNpfkHkDxQ","e":"AQAB","alg":"RSA-OAEP","use":"enc"});


    //Set the encryption options:
    var options = 
    {
        zip: false,
        compact: true,
        contentAlg: contentAlg,
        protect: Object.keys(
        {
        "alg": skey.alg,
        "kid": skey.kid,
        "enc": contentAlg
        }),
        fields: 
        {
        "alg": skey.alg,
        "kid": skey.kid,
        "enc": contentAlg
        }
    };

    //Create the encrypted token (JWE) from the signed token: (JWS + JWE)
    token  = await JWE.createEncrypt(options, skey).update(token, "utf8").final();
    return res.json({ response: 'encrypt-1', token });
});

app.get('/encrypt-2-ok', async (req, res) =>  {
    
    var key;

    await jose.JWK.createKey("oct", 256, { alg: "A128CBC-HS256" }).
    then(function(result) {
        key = result;
    });

    var json = {
        name: 'Kevin',
        cpf: 12346
    };

    var buff = Buffer.from(JSON.stringify(json)).toString("base64");
    console.log('1', buff);
    

    var jwe = await jose.JWE.createEncrypt(key).
    update(buff).
    final().
    then(function(jweEncrypted) {
        return jweEncrypted;
    });

    //decrypt
    jose.JWE.createDecrypt(key).
    decrypt(jwe).
    then(function(result) {
        //console.log(result);
        // {result} is a Object with:
        // *  header: the combined 'protected' and 'unprotected' header members
        // *  protected: an array of the member names from the "protected" member
        // *  key: Key used to decrypt
        // *  payload: Buffer of the decrypted content
        // *  plaintext: Buffer of the decrypted content (alternate)

        var payload = result.plaintext;
        var buf = Buffer.from(payload, 'base64').toString('ascii'); // Ta-da
        var buf2 = jose.util.base64url.decode(payload);
        console.log(buf2, buf);
    });

    return res.json({ response: 'encrypt-2', jwe });
});

app.get('/encrypt-3', async (req, res) =>  {
    //Set content encryption algorithm:
    var contentAlg = "A256CBC-HS512";

    //Get he server/recipient key   
    var skey = 
    {
        "kty": "RSA",
        "kid":"pdmN_UI10XD6wy44jm-JkHmJOFxevse_2jio8cH1lRw",
        "use": "enc",
        "n":"3ZWrUY0Y6IKN1qI4BhxR2C7oHVFgGPYkd38uGq1jQNSqEvJFcN93CYm16_G78FAFKWqwsJb3Wx-nbxDn6LtP4AhULB1H0K0g7_jLklDAHvI8yhOKlvoyvsUFPWtNxlJyh5JJXvkNKV_4Oo12e69f8QCuQ6NpEPl-cSvXIqUYBCs",
        "e": "AQAB",
        "alg": "RSA-OAEP",
        "alg": "RSA-OAEP",
        "key_ops": ["wrap", "verify"]
    };

    //Make the server/recipient key a JWK:
    var key = await JWK.asKey(skey);

    //Create the token payload/claim set:
    var payload = JSON.stringify({"sub": "1234567890",  "name": "Eric D.",  "role": "admin","iat": 1516239022});

    //Set up the encryption options:
    var options = 
    {
        compact: true,
        contentAlg: contentAlg,
        protect: Object.keys(
        {
        "alg": key.alg,
        "kid": key.kid,
        "enc": contentAlg
        }),
        fields: 
        {
        "alg": key.alg,
        "kid": key.kid,
        "enc": contentAlg
        }
    };

    //encrypt. the payload should be read in as a "utf8" encoding. Buffer automatically generated in update().
    var token = await JWE.createEncrypt(options, key).update(payload, "utf8").final();
    return res.json({ response: 'encrypt-jwe', token });
});
 
const jwt = require('node-webtokens');
app.get('/encrypt-4', async (req, res) =>  {
   
    const enc = 'HS256';
    var payload = {
        name: 'Kevin',
        cpf: 410322868777
      };

      const hash = returnHash();
      console.log(hash);
      var key = Buffer.from(hash).toString("base64");

    // JWE EXAMPLE
    var token = jwt.generate(enc, payload, key);
   // parsedToken = jwt.parse(token).verify(key);
    console.log(token);

    var parsedToken = jwt.parse(token).verify(key);
    console.log('parsedToken', parsedToken);
    var payload2 = parsedToken.payload;
    console.log(payload2);

    return res.json({ response: 'encrypt-4', token });
});

function returnHash(){
    abc = "abcdefghijklmnopqrstuvwxyz1234567890".split("");
    var token=""; 
    for(i=0;i<32;i++){
         token += abc[Math.floor(Math.random()*abc.length)];
    }
    return token; //Will return a 32 bit "hash"
}

const server = http.createServer(app); 
server.listen(3003);
console.log("Servidor escutando na porta 3002...")