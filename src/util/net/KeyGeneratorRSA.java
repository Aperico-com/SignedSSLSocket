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
import java.net.Socket;
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

public class KeyGeneratorRSA {
	
	private final String STORENAME = "pokeroffice.store";
	private final String STOREPASS = "5t0r3p455";
	private final String KEYPASS = "k3yp455";
	private final String ALIAS = "OFFIC";
	private final String CERTNAME = "pokeroffice.cert";
	
	private void exportCertFromStore(){
		
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
	
	private void generateKeyPair(){
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024, new SecureRandom());
			
			KeyPair kp = kpg.generateKeyPair();
			
			Class privspec = Class.forName(
							"java.security.spec.RSAPrivateKeySpec");
			Class pubspec = Class.forName(
			"java.security.spec.RSAPublicKeySpec");
			
			KeyFactory kf = KeyFactory.getInstance("RSA");
			
			RSAPrivateKeySpec privks = (RSAPrivateKeySpec)
									kf.getKeySpec(kp.getPrivate(), privspec);
			
			RSAPublicKeySpec pubks = (RSAPublicKeySpec)
			kf.getKeySpec(kp.getPublic(), pubspec);
			
			FileOutputStream fos = new FileOutputStream("priv.key");
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(privks.getModulus());
			oos.writeObject(privks.getPrivateExponent());
			//oos.writeObject(privks.getQ());
			//oos.writeObject(privks.getG());
			
			fos = new FileOutputStream("pub.key");
			oos = new ObjectOutputStream(fos);
			oos.writeObject(pubks.getModulus());
			oos.writeObject(pubks.getPublicExponent());
			//oos.writeObject(pubks.getQ());
			//oos.writeObject(pubks.getG());
			
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
			RSAPublicKeySpec ks = new RSAPublicKeySpec((BigInteger) ois
					.readObject(), (BigInteger) ois.readObject());
			KeyFactory kf = KeyFactory.getInstance("RSA");
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
			RSAPrivateKeySpec ks = new RSAPrivateKeySpec((BigInteger) ois
					.readObject(), (BigInteger) ois.readObject());
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PrivateKey pk = kf.generatePrivate(ks);

			return pk;

		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}
	
	public byte[] createSignature(){
		
		try {
			Signature sig = Signature.getInstance("SHA1withRSA");
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
		KeyGeneratorRSA kg = new KeyGeneratorRSA();
		kg.generateKeyPair();
		//kg.sendSignature();
	}

}
