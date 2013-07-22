/**
 * 
 */
package nl.tudelft.ewi.es.webid;

import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import android.util.Log;

import com.hp.hpl.jena.query.QueryExecution;
import com.hp.hpl.jena.query.QuerySolution;
import com.hp.hpl.jena.query.ResultSet;
import com.hp.hpl.jena.rdf.model.Resource;
import com.hp.hpl.jena.sparql.resultset.ResultSetException;

/**
 * @author ydurmus
 * 
 * Establishes the trust.
 * 
 * Different types of trust:
 * Act as Human: In this category the device holds its owners certificate. Therefore, 
 * the device behaves like its owner.
 * 
 * Act as Machine itself:
 * Device has its own certificate and own web profile. In the web profile it states its owners.
 * Trust is established if the owners are the same.
 * 
 * Direct Trust: Device has its own certificate and own web profile. In the web profile it states its owners.
 * In Direct Trust, trust is established if the owners  are direct friends.
 * 
 * Transitive Trust (InDirect trust): Like Direct trust, device has its own certificate and profile. 
 * But the trust is established if there is a common link (friend). 
 *
 */
public interface Validator {
	
	
	
	/**
	 * Checks for the trust link between two parties.
	 * 
	 */
	public boolean validate();

}

abstract class ValidatorCommons  {
	public  String TAG = "WebID.ValidatorCommons"; 
	
	protected X509Certificate certOfAuthority = null;
	protected X509Certificate certOfSupplicant = null;

	// # We are omitting the BlankNodes. In future we can try a recursive call.
	protected static String FIND_FRIENDS = 
					" PREFIX foaf: <http://xmlns.com/foaf/0.1/> \n"+
					" PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#> \n"+
					" SELECT DISTINCT ?friend { \n"+
					"    [] foaf:knows ?friend . \n"+
					"    FILTER isURI(?friend)  . \n"+
					"    } ";
	
	public ValidatorCommons(X509Certificate certOfAuthority, X509Certificate certOfSupplicant ){
		this.certOfAuthority = certOfAuthority;
		this.certOfSupplicant = certOfSupplicant;
	}
	
	protected List<String> fetchFriends(final String url){
		QueryExecution qexec = Util.fetchRemoteAndQuery(FIND_FRIENDS, url);
		ResultSet results = null;
		List<String> friends =  new LinkedList<String>();
		if (null == qexec){
			return friends;
		}
		try {
			results = qexec.execSelect();
			for(; null != results && results.hasNext() ;){
				QuerySolution soln = results.nextSolution() ;
				Log.d(TAG, "Friend query solution:" + soln.toString());

				Resource friend = soln.getResource("friend") ;   // Get a result variable - must be a literal
				friends.add(friend.toString());
				Log.d(TAG, "URL:"+url+" has friend:"+friend);
			}
			
		} catch (ResultSetException e) {
			Log.e(TAG, "Error in fetching the friends:"+ e.getMessage());
		} finally{results.getResourceModel().close(); qexec.close();}
		
		return friends;
	}
}
/**
  * Act as human:
	 * -------------- 
	 * Take both certificates.
	 * Since the opponent certificate has been verified skip it.
	 * Just check the owner certificate, go to its profile, check whether there is a foaf:knows link to the 
	 * SANuri of the opponent.
 */
class ActAsHuman extends ValidatorCommons implements Validator {
	
	
	public String TAG = "WebID.ActAsHuman";
	
	public ActAsHuman(X509Certificate certOfAuthority, X509Certificate certOfSupplicant ){
		super(certOfAuthority, certOfSupplicant);
	}

	@Override
	public boolean validate() {
		String authUri = Util.getSanURI(certOfAuthority);
		String suppUri = Util.getSanURI(certOfSupplicant);
		
		return authUri.equalsIgnoreCase(suppUri);
		
	}
	
}
/**
 * * Act As Machine itself:
	 * ------------ 
	 * Take both of the certificates.
	 * Get the friend list of both of the Owner and Opponent
	 * If same owner, go to its web site and verify that it knows both of the devices.
 */
class ActAsDevice extends ValidatorCommons implements Validator {
	
	public String TAG = "WebID.ActAsDevice";
	
	public ActAsDevice(X509Certificate certOfAuthority, X509Certificate certOfSupplicant ){
		super(certOfAuthority, certOfSupplicant);
		
	}

	@Override
	public boolean validate() {
		String authUri = Util.getSanURI(certOfAuthority); // Points to the web profile of the authority machine
		String suppUri = Util.getSanURI(certOfSupplicant); // Points to the web profile of the supplicant machine

		List <String> ownersOfAuthority = fetchFriends(authUri);
		List <String> ownersOfSupplicant = fetchFriends(suppUri);

		//		Log.d(TAG, "Friends of the Authority are:"+ownersOfAuthority.toString());
		//		Log.d(TAG,"Friends of the Supplicant are:"+ownersOfSupplicant.toString());


		// We found that there is a common owner. 
		// Now we should verify that the owner trusts to supplicant device. 
		// They have to be friends. 
		ownersOfAuthority.retainAll(ownersOfSupplicant);
		for(String ownerUrl : ownersOfAuthority){
			List<String> tempFriends = fetchFriends(ownerUrl);
			if(tempFriends.contains(suppUri)){
				Log.i(TAG, ownerUrl+" is the common owner for auth:"+authUri+" and supp:"+suppUri);
				return true;
			}
		}

		Log.d(TAG, "There is no common owner for auth:"+authUri+" and supp:"+suppUri);
		return false;
	}

}

/**
 * * Direct Trust:
	 * ------------
	 * Take both of the certificates.
	 * Get the friend list of both.
	 * Then for each human owner of the Owner device, check whether any of them knows, any of the opponent owners.
	 * If one of them true, then check that opponent knows the opponent device.
	 * PROBLEM: After the first connection, search stops, what about better matches?
 * */
class DirectTrust extends ValidatorCommons implements Validator {
	public String TAG = "WebID.DirectTrust";

	public DirectTrust(X509Certificate certOfAuthority, X509Certificate certOfSupplicant ){
		super(certOfAuthority, certOfSupplicant);
	}
	
	@Override
	public boolean validate() {
		String authUri = Util.getSanURI(certOfAuthority); // Points to the web profile of the authority machine
		String suppUri = Util.getSanURI(certOfSupplicant); // Points to the web profile of the supplicant machine

		List <String> ownersOfAuthority = fetchFriends(authUri);
		List <String> ownersOfSupplicant = fetchFriends(suppUri);

		for(String ownerUri : ownersOfAuthority){

			List <String> friendsOfOwner = fetchFriends(ownerUri);

			// Is Any of the friends owner of the supplicant? 
			friendsOfOwner.retainAll(ownersOfSupplicant);
			for(String friend : friendsOfOwner){
				List<String> tempFriends = fetchFriends(friend);
				if(tempFriends.contains(suppUri)){
					Log.i(TAG, friend+" is the friend of the owner of the machine");
					return true;
				}
			}
		}

		return false;
	}

}


/**
 * * InDirect (Transitive) Trust:
	 * ------------
	 * Take both of the certificates.
	 * Get the friend list of both.
	 * Each friend of the authority is in fact one of the device owners.
	 * So fetch each of the device owner web profile with their friend profile.
	 * Then go each of these intermediate friends till you see one of them knows any of the supplicant owners.
	 * 
 * */
class InDirectTrust extends ValidatorCommons implements Validator {
	public String TAG = "WebID.InDirectTrust";

	public InDirectTrust(X509Certificate certOfAuthority, X509Certificate certOfSupplicant ){
		super(certOfAuthority, certOfSupplicant);
	}
	
	private void fillFriendlists(List <String> owners, Set <String> friendsofOwners,HashMap<String, List<String>> friendMap, String deviceUri, Set <String> blackList){
		for(String owner : owners){
			List <String> temp = fetchFriends(owner);
			if(null != deviceUri && !temp.contains(deviceUri)){ 
				blackList.add(owner);
				Log.w(TAG, "Hey Suppliicant:" + deviceUri + " is lying about:"+owner);
				// Complicated isn't it :P
				continue;
			}
			friendsofOwners.addAll(temp);
			for(String f: temp){
				if(friendMap.containsKey(f)){
					friendMap.get(f).add(owner);
				}else {
					List <String> l = new LinkedList<String>();
					l.add(owner);
					friendMap.put(f, l);
				}
			}
		}
	}
	
	@Override
	public boolean validate() {
		String authUri = Util.getSanURI(certOfAuthority); // Points to the web profile of the authority machine
		String suppUri = Util.getSanURI(certOfSupplicant); // Points to the web profile of the supplicant machine

		List <String> ownersOfAuthority = fetchFriends(authUri);
		List <String> ownersOfSupplicant = fetchFriends(suppUri);
		
		Log.d(TAG, "Owners of the authority("+authUri+") are: " + ownersOfAuthority.toString());
		Log.d(TAG, "Owners of the supplicant("+suppUri+") are: " + ownersOfSupplicant.toString());
		
		Set <String> friendsOftheAuthOwners = new HashSet<String>();
		Set <String> friendsOftheSuppOwners = new HashSet<String>();
		
		
		
		HashMap<String, List<String>> friendMap =  new HashMap<String, List<String>>();
		// The Supplicant device can claim that Obama owns it. However, we should be sure that Obama
		// really owns the device. Therefore, while checking the friends of Obama, we will also check for the 
		// supplicant device. If supplicant device does not exist, Obama goes to black list.
		Set <String> blackListOfSupplicantOwners = new HashSet<String>(); 
		
		fillFriendlists(ownersOfAuthority, friendsOftheAuthOwners, friendMap,null,null);
		fillFriendlists(ownersOfSupplicant, friendsOftheSuppOwners, friendMap, suppUri,blackListOfSupplicantOwners);
		
		Log.d(TAG,"Friends of the auth owners are:"+friendsOftheAuthOwners);
		Log.d(TAG,"Friends of the Supp owners are:" +friendsOftheSuppOwners);
		Log.d(TAG,"Black list for supp:"+blackListOfSupplicantOwners);
		
		friendsOftheAuthOwners.retainAll(friendsOftheSuppOwners);
		Log.d(TAG, "Common friends are:"+friendsOftheAuthOwners);
		
		for(String friend : friendsOftheAuthOwners){
			//Check if the friend on leaf of the social network knows the Owners of Supplicant who claim that they know this guy
			List<String> tempFriends = fetchFriends(friend);
			tempFriends.retainAll(friendMap.get(friend)); // if tempFriends.size > 0 then we are sure that supp owner and its claimed friend are really friends indeed
			Log.d(TAG,"Hey common friend knows these supplicant owners:"+tempFriends.toString());
			// If we have found a common friend now lastly we should be sure that supplicant Owner really owns the device.
			// Device can claim someone who is unrelated owns the device, and exploit its social network.
			tempFriends.removeAll(blackListOfSupplicantOwners);
			if (tempFriends.size() > 0){
				//Hey we have found a connection!!!
				
				Log.i(TAG, "The common friend is:"+friend+" known by one of these supp owners:"+tempFriends.toString());
				return true;
			}
		}
		
		
		return false;
	}
	
}