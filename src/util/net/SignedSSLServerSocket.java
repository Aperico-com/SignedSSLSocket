package util.net;

/**
 * @author Andreas E Toresäter
 * Copyright 2005 PokerOffice AB, all rights reserved.
 */

import java.io.BufferedInputStream;
import java.io.FileInputStream;
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
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SignedSSLServerSocket extends SSLServerSocket {

	// Path to public key
	private final String publicKeyName = "pub.key";

	// Set this to true to get verbose output
	private boolean verbose;
	
	private boolean listen;

	// Servers port number
	private int port;

	SSLServerSocket serverSocket;
	
	/**
	 * Constructor for wrapping a Server Socket into a Signed SSL Server Socket
	 * @param serverSocket ServerSocket - ServerSocket to be wrapped
	 * @param port int - port number
	 * @param verbose boolean - if output to System.out should be generated
	 * @throws IOException
	 */
	public SignedSSLServerSocket(ServerSocket serverSocket, int port,
			boolean verbose) throws IOException {
		this.serverSocket = (SSLServerSocket) serverSocket;
		this.verbose = verbose;
		this.port = port;
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
			// Get signature from Socket then verify it
			byte[] signature = readSignature(s);
			if (verifySignature(signature)) {
				if (isVerbose()) {
					System.out.println("Connection accepted");
				}
				return true;
			} else {
				return false;
			}
		} else {

			if (isVerbose()) {
				System.out.println("Connection dropped");
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
	 * 
	 * @param s SSLSocket - SSLSocket to read from
	 * @return byte[] - byte array containing signature
	 */
	private byte[] readSignature(SSLSocket s) {
		// byte array to hold the signature
		byte[] signature = new byte[512];

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
		}

		return signature;
	}

	/**
	 * Verifies a SHA1withDSA (512) signature
	 * @param signature byte[] - byte array containing the signature to be verified
	 * @return boolean - true if signature is verified
	 */
	private boolean verifySignature(byte[] signature) {

		// import public key
		PublicKey pubKey = importPublicKey();

		try {
			Signature sig = Signature.getInstance("SHA1withDSA");
			sig.initVerify(pubKey);
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
			
			// Create a Server Socket
			ServerSocket ss = SSLServerSocketFactory.getDefault().createServerSocket(9999);
			
			// Wrap the Server Socket with a Signed SSL Server Socket
			SignedSSLServerSocket sss = new SignedSSLServerSocket(ss, 9999, true);
			
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

	public int getPort() {
		return port;
	}

	public void setPort(int port) {
		this.port = port;
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

}
