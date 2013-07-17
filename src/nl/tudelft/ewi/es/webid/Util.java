/**
 * 
 */
package nl.tudelft.ewi.es.webid;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Scanner;

import android.content.Context;
import android.util.Log;

import com.hp.hpl.jena.query.QueryExecution;
import com.hp.hpl.jena.query.QueryExecutionFactory;
import com.hp.hpl.jena.rdf.arp.JenaReader;
import com.hp.hpl.jena.rdf.model.Model;
import com.hp.hpl.jena.rdf.model.ModelFactory;

/**
 * @author ydurmus
 *
 */
public class Util {

	private static String TAG = "WebID.Util";
	private static final int URIfieldTag = 6; // Look above
	
	public static X509Certificate generateX509Cert(String mCert) throws CertificateException{
		CertificateFactory factory;

		factory = CertificateFactory.getInstance("X.509");
		BufferedInputStream in = 
				new BufferedInputStream(new ByteArrayInputStream(mCert.getBytes()));
		return (X509Certificate) factory.generateCertificate(in);
	}
	
	
	/**
	 * Returns the first Subject Alternative Name,URI field of the first certificate that has the value.
	 * 
	 * * GeneralName ::= CHOICE {
      otherName                       [0]     AnotherName,
      rfc822Name                      [1]     IA5String,
      dNSName                         [2]     IA5String,
      x400Address                     [3]     ORAddress,
      directoryName                   [4]     Name,
      ediPartyName                    [5]     EDIPartyName,
      uniformResourceIdentifier       [6]     IA5String, <<<<<<<<<< What we are looking for
      iPAddress                       [7]     OCTET STRING,
      registeredID                    [8]     OBJECT IDENTIFIER }
	 * 
	 * Returns null if non found.
	 * */
	public static String getSanURI(X509Certificate cert){
		try {
			
			Collection<List<?>> sans;
			sans = cert.getSubjectAlternativeNames();
			Log.d(TAG,sans.toString());
			for (List<?> san : sans) {

				if ((Integer)san.get(0) == URIfieldTag ){
					return (String) san.get(1);
				}
			}


		} catch (CertificateParsingException e) {
			Log.e(TAG, "parsing error:" + e.getMessage());
			return null;
		} catch (Exception e) {
			Log.e(TAG, "error:" + e.getMessage());
			return null;
		}

		return null;
	}
	
	
	public static QueryExecution fetchRemoteAndQuery(final String query, final String serviceUrl){

		Model model = ModelFactory.createDefaultModel() ;
		JenaReader reader =  new JenaReader();
		reader.read(model, serviceUrl);
		Log.d(TAG,"Here is our model:\n" + model.toString());
		return QueryExecutionFactory.create(query, model) ;


	}
	
	public static String readCertString(int rawid, Context cont){

		
		InputStream is = cont.getResources().openRawResource(rawid);
		
		
 		Scanner scan = new Scanner(is,"UTF-8");
		StringBuilder cert = new StringBuilder();

		try {
			
			boolean flag =  false;
			
			scan.useDelimiter("\n");
			while(scan.hasNext()){
				String temp = scan.next();
				if(!flag && temp.startsWith("-----BEGIN")){
					flag = true;
					cert.append(temp);cert.append("\n");
				}else if(flag){
					cert.append(temp); cert.append("\n");
				}
			}
			
			
			
			is.close(); scan.close();

		} catch (IOException e) {
			Log.e(TAG,"cannot read the raw certificate file:"+e.getMessage());
		} 
		return cert.toString();

	}
	


	
}
