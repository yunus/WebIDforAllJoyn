/**
 * 
 */
package nl.tudelft.ewi.es.webid;

import java.security.cert.CertificateException;

import android.util.Log;

/**
 * @author ydurmus
 *
 */
public class ValidatorFactory {
	
	private static String TAG = "WebID.ValidatorFactory";

	public static Validator generateValidator(String type, String authCert, String suppCert) {

		try {
			if (type.equals("ActAsHuman")){	return new ActAsHuman(Util.generateX509Cert(authCert), Util.generateX509Cert(suppCert));} 
			else if (type.equals("ActAsDevice") || type.equals("SameOwner") ){ return new ActAsDevice(Util.generateX509Cert(authCert), Util.generateX509Cert(suppCert));}
			else if (type.equals("DirectTrust")){ return new DirectTrust(Util.generateX509Cert(authCert), Util.generateX509Cert(suppCert));}
			else if (type.equals("InDirectTrust")){ return new InDirectTrust(Util.generateX509Cert(authCert), Util.generateX509Cert(suppCert));}
		} catch (CertificateException e) {
			Log.d(TAG, "Could not create the validator object. Certificate creation error: "+ e.getMessage());
		}
		return null;
	}
	
	

}
