package nl.tudelft.ewi.es.webid;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import android.util.Log;

import com.hp.hpl.jena.query.QueryExecution;
import com.hp.hpl.jena.query.QuerySolution;
import com.hp.hpl.jena.query.ResultSet;
import com.hp.hpl.jena.rdf.model.Literal;
import com.hp.hpl.jena.sparql.resultset.ResultSetException;

/**
 * 
 */

/**
 * @author ydurmus
 * 
 * Verifies the WebID by checking the modulus and exponent in the given certificate.
 * Parses the certificate, extracts the URI in Subject Alternative Name field. Then using 
 * SPARQL (Android ARQ) checks whether the modulus and the exponent are the same in the website 
 * pointed by the URI and the mod, exp in the certificate.
 *
 */
public class Verify {
	

	
	
	private static final String TAG = "WebID Verify ";
	private static final String WEBID_MOD_EXP = " PREFIX cert: <http://www.w3.org/ns/auth/cert#> \n"+
			"PREFIX rsa: <http://www.w3.org/ns/auth/rsa#> \n"+
			"SELECT ?mod ?exp \n"+
			"WHERE { [] cert:key [ \n"+
			"        cert:modulus ?mod; \n"+
			"        cert:exponent ?exp; \n"+
			"       ] . \n"+
			"}";
			
	
	
    public  String mCert;
    private X509Certificate cert;
    
	
	public Verify  (final String certificateChain ) throws CertificateException, IOException {
			     	mCert = certificateChain;
			     	cert = Util.generateX509Cert(mCert);
	        
	        Log.d(TAG,"Verify object has been created");
	}
	
	
	private String getModulus(){
		RSAPublicKey rsa = (RSAPublicKey) cert.getPublicKey();
		
		return rsa.getModulus().toString(16);
		
	}
	
	private BigInteger getExponent(){
		RSAPublicKey rsa = (RSAPublicKey) cert.getPublicKey();
		return rsa.getPublicExponent();
	}

	
	
	

	
	

	public boolean verify(){
		String service = Util.getSanURI(cert);
		Log.d(TAG, "Now we will verify the SAN, ("+service+")");
		if(null == service) {
			Log.e(TAG,"Could not find any URI in the certificate");
			return false;
		}

		BigInteger exponent = getExponent();
		String modulusinhex = getModulus();
		Log.d(TAG, "Original modulus: \n"+ modulusinhex+ "\n Exponent: "+ exponent);

		
		QueryExecution qexec = Util.fetchRemoteAndQuery(WEBID_MOD_EXP, service);
		ResultSet results= null;
		
		try{
			
			results = qexec.execSelect() ;
			for ( ; null != results && results.hasNext() ; )
			{

				QuerySolution soln = results.nextSolution() ;

				Literal mod = soln.getLiteral("mod") ;   // Get a result variable - must be a literal
				Literal exp = soln.getLiteral("exp");

				Log.d(TAG,"Modulus is :\n " + mod.getLexicalForm() + "\n Exponent is : "+ exp.getInt());

				if(mod.getLexicalForm().equalsIgnoreCase(modulusinhex) && exp.getInt() == exponent.intValue()){
					Log.d(TAG, "VERIFIED");
					return true;
				}
			}
		} catch(ResultSetException ex){
			Log.e(TAG,"Exception in the result set: "+ ex.getMessage());
		}finally{ results.getResourceModel().close(); qexec.close();}



		return false;
	}


}
