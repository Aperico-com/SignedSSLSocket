package util.net;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * @author Andreas E Toresäter
 **/

/**
 * Test class for connectiong to a Signed SSL Server
 */
public class SignedSSLClientRSA {

	private static final String ALIAS = "OFFIC";
	
	private final String STORENAME = "pokeroffice.store";
	private final String STOREPASS = "k3yp455";
	private final String KEYPASS = "k3yp455";

	//private static final int PORT = 9999;
	private int PORT = 5555;
	
	public SignedSSLClientRSA(){
		System.setProperty("javax.net.ssl.trustStore",
				STORENAME);
		
		System.setProperty("javax.net.ssl.trustStorePassword",
				STOREPASS);
	}
	
	/**
	 * Imports the private key from a keystore
	 * @return - PrivateKey, the key imported from file
	 */
	private PrivateKey importPrivateKeyFromStore() {
		try {
			KeyStore ks = KeyStore.getInstance("JKS");
			FileInputStream ksfis = new FileInputStream(STORENAME); 
			BufferedInputStream ksbufin = new BufferedInputStream(ksfis);  
			
			ks.load(ksbufin, STOREPASS.toCharArray());
			PrivateKey priv = (PrivateKey) ks.getKey(ALIAS, KEYPASS.toCharArray());
			
			return priv;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}


	public byte[] createSignature() {

		try {
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initSign(importPrivateKeyFromStore());
			byte[] signature = sig.sign();

			System.out.println("Signature created with length:"
					+ signature.length);

			return signature;
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return null;
	}

	private void handleInputStream(SSLSocket s) {

		BufferedInputStream bis = null;
		try {
			bis = new BufferedInputStream(s.getInputStream());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		System.err.println("<i>Client connected to server (B2B)</i>");
		String message = "";
		
		// Get the sockets input stream
		while (true) {

			try {
				int testByte = bis.read();
				// get message
				if (testByte != -1) {
					byte[] testByteArray = new byte[1];
					testByteArray[0] = new Integer(testByte).byteValue();
					byte[] byteArray = new byte[1024];
					bis.read(byteArray);
					message = new String(testByteArray)
							+ new String(byteArray).trim();
					System.err.println("<msg>" + message + "</msg>");

				}
				else{
					break;
				}
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				break;
			}

		}
	}

	private SSLSocket sendAliasAndSignature() {
		SSLSocket s = null;

		try {
			s = (SSLSocket) SSLSocketFactory.getDefault().createSocket(
					"127.0.0.1", PORT);
		} catch (UnknownHostException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		// get output and input streams from the socket
		OutputStream os = null;

		try {
			os = s.getOutputStream();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		// create signature
		byte[] sig = createSignature();

		// send alias
		try {
			os.write(ALIAS.getBytes());
			os.write(sig);
			os.flush();
			System.out.println("Alias and Signature sent");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return s;
		
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		
		


		// TODO Auto-generated method stub
		SignedSSLClientRSA ssslc = new SignedSSLClientRSA();
		
		ssslc.PORT = 5432;//Integer.parseInt(args[0]);

		SSLSocket s = ssslc.sendAliasAndSignature();
//		 handle the input stream
		ssslc.handleInputStream(s);
	}

}
