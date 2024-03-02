import json
import datetime
import uuid
from base64 import urlsafe_b64encode
from flask import Flask, jsonify, request
import rsa   #this allows generation of keys
import jwt    #jwt is a library designed just for this.py



app = Flask(__name__) 
#public key is used for encryption/verifying signature, private drcryption/signing
my_jwks=[]
@app.route("/.well-known/jwks.json", methods=["GET"]) #when the well known jwks is activated, return a jwks of all jwk's on the server. I think the jwks is compiled automatically at the wellknownjwks.json?
def get_jwks():    #should return JWKS
    i=0
    while i< len(my_jwks):
        if my_jwks[i]['exp'] < datetime.datetime.utcnow(): #if key is expired...        
            del my_jwks[i]    #get rid of that jwk
        else:
            i+=1
    jwks = {"keys": my_jwks}    #Then Jsonify what's left and return the JWKS!
    return jsonify(jwks)



@app.route("/auth", methods=["POST"])   #creates a JWK (public key associated with private key) and returns a corresponding JWT
def create_jwt():
    expired = request.args.get('expired')   # if ?expired=true, then it generates an expired token
    print ("post connected")
    public_key, private_key = rsa.newkeys(2056) #creates a public/private keypair
    n=public_key.n
    e=public_key.e
    # Export public key in PKCS#1 format, PEM encoded 
    public_key = public_key.save_pkcs1().decode('utf8')
    # Export private key in PKCS#1 format, PEM encoded 
    private_key = private_key.save_pkcs1().decode('utf8')
    kid = uuid.uuid1()          #should make a unique key id
    kid = str(kid)              #converts kid to string so it can be written
    n=urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big'))
    e=urlsafe_b64encode(e.to_bytes((e.bit_length() + 7) // 8, byteorder='big'))
    n=n.decode("utf-8").rstrip('=')
    e=e.decode('utf-8')
    if(expired == 'true'):
        print("SUPPOSED TO BE EXPIRED")
        payload={'exp':datetime.datetime.utcnow()} #60 seconds
        this_jwk = {    #this creates the jwk.
    'kty': 'RSA',
    'alg': 'RS256',
    'use':'sig',
    'n': n,
    'e': e,
    'kid': kid,
    'exp':datetime.datetime.utcnow()
        }
    else:
        payload={'exp':datetime.datetime.utcnow() + datetime.timedelta(days=0,seconds=30)} 
        this_jwk = {
    'kty': 'RSA',
    'alg': 'RS256',
    'use':'sig',
    'n': n,
    'e': e,
    'kid': kid,
    'exp':datetime.datetime.utcnow() + datetime.timedelta(days=0,seconds=60)
        }
    #with open("jwks.json", "a") as outfile:
    #    outfile.write(this_jwk)
    my_jwks.append(this_jwk)   #adds this to the set of JWK's
    access_token = jwt.encode(payload,private_key,algorithm='RS256',headers={'kid':kid})
    return access_token               #returns signed jwt

if __name__ == "__main__":
    app.run(port=8080)
