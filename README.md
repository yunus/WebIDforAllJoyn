
[WebID](https://dvcs.w3.org/hg/WebID/raw-file/tip/spec/identity-respec.html) android library for [AllJoyn](https://www.alljoyn.org/).

WebID is a single sign on standard, and AllJoyn helps you create a proximity based 
peer2peer network without dealing with communication interfaces.
When you combine the two you get social devices.

Devices have their own x509 certificates and web profiles. In the web profiles 
they declare their owners. And by using the social networks of the owners of the devices
services in AllJoyn are authenticated.

And this library does it :). In AllJoyn RSA based key exchange mechanism for authentication.
It uses X509 certificates. But it leaves the verification of the certificates to the application developers.
At this point, our library comes into play. We "verify" the certificate by checking the 
public key information at the web profile (see WebID) and then "validate" 
the trust connection.

For the time being you have to select which type of social network search that you want.

- "ActAsHuman" : certificate belongs to human
- "ActAsDevice" : certificate belongs to device itself and the devices have the same owner.
- "DirectTrust" : certificate belongs to device itself and the devices owners are direct friends.
- "InDirectTrust" : certificate belongs to device itself and the devices owners are indirect friends, namely they have a common friend.


The code is highly experimental (implemented in two days). Use with your own risk. You can ask me before using it. 


How TO:
AllJoyn has samples for RSA key exchange which uses  RSAKeyXListener class.
The requested method of RSAKeyXListener class is called several times for 
sending your own public certificate and verifying a received one.

I have copy pasted the part of the code that I have implemented those. You will understand when 
you see the original sample.

'''java
			if (verifyRequest != null) {
                /* Verify a certificate chain supplied by the peer. */
            	Log.d(TAG ," in verify");
            	
            	CertificateFactory factory;
            	try {
					factory = CertificateFactory.getInstance("X.509");
					String chain = verifyRequest.getCertificateChain();			        
			        
			        Verify v = new Verify(chain);
			        // For the time being I have embedded the certificate. 
			        // In production user should be able to choose
			        mCert = Util.readCertString(R.raw.MyPublicCertInSTRINGandPEMFormat,getApplicationContext());
			        Validator valid = ValidatorFactory.generateValidator("InDirectTrust", mCert, chain);
			        
			        return v.verify() && valid.validate();
			        
					
				} catch (CertificateParsingException e) {
					
					Log.e(TAG,"Certificate parsing exception: " + e.getMessage());
					return false;
				}catch (CertificateException e) {					
				
					Log.e(TAG,"Certificate exception: " + e.getMessage());
					return false;
				} catch (IOException e) {
					Log.e(TAG,"IO exception: " + e.getMessage());
					return false;
				}
            	
                
            } else if (certificateRequest != null && 
                    privateKeyRequest != null &&
                    passwordRequest != null ) {
                /* 
                 * The engine is asking us for our certificate chain.  
                 *
                 * If we return true and do not supply the certificate chain, then the engine will
                 * create a self-signed certificate for us.  It will ask for the passphrase to use
                 * for the private key via a PasswordRequest. 
                 */
            	Log.d(TAG ," in certificate request");
            	mCert = Util.readCertString(R.raw.MyPublicCertInSTRINGandPEMFormat,getApplicationContext());
            	mPrivateKey = Util.readCertString(R.raw.MyPrivateKeyInSTRINGandPEMFormat,getApplicationContext());
            	            	
            	passwordRequest.setPassword(mPassword.toCharArray());
                privateKeyRequest.setPrivateKey(mPrivateKey);
                certificateRequest.setCertificateChain(mCert);
                return true;
            }

'''
