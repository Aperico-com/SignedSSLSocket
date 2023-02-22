package util.net;

import java.io.FileInputStream;
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
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
* @author Andreas E Toresäter
**/

/**
 * Test class for connectiong to a Signed SSL Server
 */
public class SignedSSLClient {

	private void generateKeyPair(){
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("DSA");
			kpg.initialize(512, new SecureRandom());
			
			KeyPair kp = kpg.generateKeyPair();
			
			Class privspec = Class.forName(
							"java.security.spec.DSAPrivateKeySpec");
			Class pubspec = Class.forName(
			"java.security.spec.DSAPublicKeySpec");
			
			KeyFactory kf = KeyFactory.getInstance("DSA");
			
			DSAPrivateKeySpec privks = (DSAPrivateKeySpec)
									kf.getKeySpec(kp.getPrivate(), privspec);
			
			DSAPublicKeySpec pubks = (DSAPublicKeySpec)
			kf.getKeySpec(kp.getPublic(), pubspec);
			
			FileOutputStream fos = new FileOutputStream("priv.key");
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(privks.getX());
			oos.writeObject(privks.getP());
			oos.writeObject(privks.getQ());
			oos.writeObject(privks.getG());
			
			fos = new FileOutputStream("pub.key");
			oos = new ObjectOutputStream(fos);
			oos.writeObject(pubks.getY());
			oos.writeObject(pubks.getP());
			oos.writeObject(pubks.getQ());
			oos.writeObject(pubks.getG());
			
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * Imports the public key from file
	 * @return - PublicKey, the key imported from file
	 */
	private PublicKey importPublicKey() {
		try {
			FileInputStream fis = new FileInputStream("pub.key");
			ObjectInputStream ois = new ObjectInputStream(fis);
			DSAPublicKeySpec ks = new DSAPublicKeySpec((BigInteger) ois
					.readObject(), (BigInteger) ois.readObject(),
					(BigInteger) ois.readObject(), (BigInteger) ois
							.readObject());
			KeyFactory kf = KeyFactory.getInstance("DSA");
			PublicKey pk = kf.generatePublic(ks);

			return pk;

		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}
	
	/**
	 * Imports the public key from file
	 * @return - PublicKey, the key imported from file
	 */
	private PrivateKey importPrivateKey() {
		try {
			FileInputStream fis = new FileInputStream("priv.key");
			ObjectInputStream ois = new ObjectInputStream(fis);
			DSAPrivateKeySpec ks = new DSAPrivateKeySpec((BigInteger) ois
					.readObject(), (BigInteger) ois.readObject(),
					(BigInteger) ois.readObject(), (BigInteger) ois
							.readObject());
			KeyFactory kf = KeyFactory.getInstance("DSA");
			PrivateKey pk = kf.generatePrivate(ks);

			return pk;

		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}
	
	public byte[] createSignature(){
		
		try {
			Signature sig = Signature.getInstance("SHA1withDSA");
			sig.initSign(importPrivateKey());
			byte[] signature = sig.sign();
			
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
	
	private void sendSignature(){
		SSLSocket s =null;
		try {
			s = (SSLSocket)SSLSocketFactory.getDefault().createSocket("127.0.0.1",
					9999);
			
			OutputStream os = s.getOutputStream();
			
			byte[] sig = createSignature();
			//sig[0]=0;
			
			os.write(sig);
			os.flush();
			os.close();
			
		} catch (UnknownHostException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		SignedSSLClient ssslc = new SignedSSLClient();
		//kg.generateKeyPair();
		ssslc.sendSignature();
	}


}
