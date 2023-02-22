package util.net;

/**
 * @author Andreas E Toresäter
 * Copyright 2005 PokerOffice AB, all rights reserved.
 */

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
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
//import java.security.spec.RSAParameterSpec;
import java.security.cert.CertificateException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SignedSSLServerSocketRSA extends SSLServerSocket {

	// Path to public key
	private final String publicKeyName = "pub.key";
	private final String STORENAME = "pokeroffice.store";
	private final String STOREPASS = "k3yp455";
	private final String KEYPASS = "k3yp455";
	private final String ALIAS = "OFFIC";
	private final String CERTNAME = "pokeroffice.cert";

	// Set this to true to get verbose output
	private boolean verbose;
	
	private boolean listen;

	// Servers port number
	private int PORT;

	SSLServerSocket serverSocket;
	
	/**
	 * Constructor for wrapping a Server Socket into a Signed SSL Server Socket
	 * @param serverSocket ServerSocket - ServerSocket to be wrapped
	 * @param port int - port number
	 * @param verbose boolean - if output to System.out should be generated
	 * @throws IOException
	 */
	public SignedSSLServerSocketRSA(ServerSocket serverSocket, int port,
			boolean verbose) throws IOException {
		this.serverSocket = (SSLServerSocket) serverSocket;
		this.verbose = verbose;
		this.PORT = port;
	}

	/**
	 * Verifies a SSLSocket
	 * @param s SSLSocket - SSLSocket to be verified
	 * @return boolean - true if SSLSocket is verified
	 */
	private boolean verifyConnection(SSLSocket s) {
		if (isVerbose()) {
			System.out.println("Connection attempted");
			System.out.println("Connecting host name: "
					+ s.getInetAddress().getHostName());

		}

		// Test the connecting Socket to see if it is from localhost.
		// If it is not, drop it.
		if (s.getInetAddress().getHostName().equalsIgnoreCase("localhost")) {

			// Connection came from localhost
			// get alias
			getAlias(s);
			
			// Get signature from Socket then verify it
			byte[] signature = readSignature(s);
			if (verifySignature(signature)) {
				if (isVerbose()) {
					System.out.println("Correct Signature, connection accepted");
				}
				return true;
			} else {
				System.out.println("Wrong signature, connection dropped");
				return false;
			}
		} else {

			if (isVerbose()) {
				System.out.println("Not connecting from localhost, connection dropped");
			}
			return false;
		}
	}

	
	 public Socket accept() throws IOException { 
		 return serverSocket.accept(); 
		}

	/**
	 * Imports the public key from file
	 * @return - PublicKey, the key imported from file
	 */
	private PublicKey importPublicKey() {
		try {
			FileInputStream fis = new FileInputStream(publicKeyName);
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
	 * Imports the public key from a keystore
	 * @return - PublicKey, the key imported from file
	 */
	private PublicKey importPublicKeyFromCert() {
		try {
			FileInputStream certfis = new FileInputStream(CERTNAME);
			java.security.cert.CertificateFactory cf =
				java.security.cert.CertificateFactory.getInstance("X.509");
			java.security.cert.Certificate cert = cf.generateCertificate(certfis);
			PublicKey pub = cert.getPublicKey();
			
			return pub;
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	private void getAlias(SSLSocket s){
//		 byte array to hold the signature
		byte[] alias = new byte[5];

		// read signature from the connecting Sockets stream
		BufferedInputStream in = null;
		
		// Get the sockets input stream
		try {
			in = new BufferedInputStream(s.getInputStream());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		int cnt = 0;

		// read byte by byte
		while (true) {

			int testByte = 0;
			try {
				testByte = in.read();
			} catch (IOException e) {
				e.printStackTrace();
				break;
			}
			if (testByte != -1) {
				alias[cnt] = new Integer(testByte).byteValue();
				cnt++;
			} else
				break;
			
			if(cnt>=5)
				break;
		}	

		System.out.println("Bytes read:"+cnt);
		System.out.println("Alias is:"+new String(alias));
	}

	/**
	 * 
	 * @param s SSLSocket - SSLSocket to read from
	 * @return byte[] - byte array containing signature
	 */
	private byte[] readSignature(SSLSocket s) {
		// byte array to hold the signature
		byte[] signature = new byte[128];

		// read signature from the connecting Sockets stream
		BufferedInputStream in = null;
		
		// Get the sockets input stream
		try {
			in = new BufferedInputStream(s.getInputStream());
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		int cnt = 0;

		// read byte by byte
		while (true) {

			int testByte = 0;
			try {
				testByte = in.read();
			} catch (IOException e) {
				e.printStackTrace();
				break;
			}
			if (testByte != -1) {
				signature[cnt] = new Integer(testByte).byteValue();
				cnt++;
			} else
				break;
			
			if(cnt>=128)
				break;
		}

		System.out.println("Bytes read:"+cnt);
		
		return signature;
	}

	/**
	 * Verifies a SHA1withRSA (512) signature
	 * @param signature byte[] - byte array containing the signature to be verified
	 * @return boolean - true if signature is verified
	 */
	private boolean verifySignature(byte[] signature) {

		// import public key
		PublicKey pubKey = importPublicKeyFromCert();

		try {
			Signature sig = Signature.getInstance("SHA1withRSA");
			sig.initVerify(pubKey);
			//String hash= "alamakota";
			//sig.update(hash.getBytes());

			if (sig.verify(signature))
				return true;

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

		return false;

	}

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		try {
//			System.setProperty("javax.net.ssl.trustStore", "C:\\eclipse\\workspace\\Signed Server Socket\\pokeroffice.store" );
//			System.setProperty("javax.net.ssl.keyStore", "C:\\eclipse\\workspace\\Signed Server Socket\\pokeroffice.store" );

			// Create a Server Socket
			ServerSocket ss = SSLServerSocketFactory.getDefault().createServerSocket(Integer.parseInt(args[0]));
			
			// Wrap the Server Socket with a Signed SSL Server Socket
			SignedSSLServerSocketRSA sss = new SignedSSLServerSocketRSA(ss, Integer.parseInt(args[0]), true);
			
			// Set the Server to listen for new connections
			sss.setListen(true);

			// Listen for connections
			while (sss.isListen()) {
				
				// Accept connections
				SSLSocket s = (SSLSocket) sss.accept();

				// Verify connections
				if (sss.verifyConnection(s)) {
					// Connection is verified
					// Do whatever you need to do with it
					if(sss.isVerbose())
						System.out.println("Got Signed SSL Server Socket");
					
					s.getOutputStream().write("HandHistory message".getBytes());
					s.getOutputStream().flush();
					
					s.getOutputStream().write("HandHistory message 2".getBytes());
					s.getOutputStream().flush();
					
				} else {
					if(sss.isVerbose())
						System.out.println("Got NULL Socket");
				}
			}

			
			
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	public boolean isVerbose() {
		return verbose;
	}

	public void setVerbose(boolean verbose) {
		this.verbose = verbose;
	}



	public String[] getEnabledCipherSuites() {
		return serverSocket.getEnabledCipherSuites();
	}

	public String[] getEnabledProtocols() {
		return serverSocket.getEnabledProtocols();
	}

	public boolean getEnableSessionCreation() {
		return serverSocket.getEnableSessionCreation();
	}

	public boolean getNeedClientAuth() {
		return serverSocket.getNeedClientAuth();
	}

	public String[] getSupportedCipherSuites() {
		return serverSocket.getSupportedCipherSuites();
	}

	public String[] getSupportedProtocols() {
		return serverSocket.getSupportedProtocols();
	}

	public boolean getUseClientMode() {
		return serverSocket.getUseClientMode();
	}

	public boolean getWantClientAuth() {
		return serverSocket.getWantClientAuth();
	}

	public void setEnabledCipherSuites(String[] suites)
			throws IllegalArgumentException {
		serverSocket.setEnabledCipherSuites(suites);
	}

	public void setEnabledProtocols(String[] protocols)
			throws IllegalArgumentException {
		serverSocket.setEnabledProtocols(protocols);
	}

	public void setEnableSessionCreation(boolean flag) {
		serverSocket.setEnableSessionCreation(flag);
	}

	public void setNeedClientAuth(boolean need) {
		serverSocket.setNeedClientAuth(need);
	}

	public void setUseClientMode(boolean mode) throws IllegalArgumentException {
		serverSocket.setUseClientMode(mode);
	}

	public void setWantClientAuth(boolean want) {
		serverSocket.setWantClientAuth(want);
	}

	public boolean isListen() {
		return listen;
	}

	public void setListen(boolean listen) {
		this.listen = listen;
	}

	public int getPORT() {
		return PORT;
	}

	public void setPORT(int port) {
		PORT = port;
	}

}
