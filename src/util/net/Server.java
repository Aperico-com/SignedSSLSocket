package util.net;

	
	import java.io.IOException;
	import java.net.InetAddress;
	import java.net.ServerSocket;
	import java.net.Socket;
	import java.net.SocketAddress;
	import java.net.SocketException;
	import java.nio.channels.ServerSocketChannel;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

	public class Server extends SSLServerSocket {
	  protected SSLServerSocket _socket;
	  public Server(ServerSocket socket) throws IOException {
	    _socket = (SSLServerSocket) socket;
	  }

	  public String[] getEnabledCipherSuites() {
	    return _socket.getEnabledCipherSuites();
	  }

	  public String[] getEnabledProtocols() {
	    return _socket.getEnabledProtocols();
	  }

	  public boolean getEnableSessionCreation() {
	    return _socket.getEnableSessionCreation();
	  }

	  public boolean getNeedClientAuth() {
	    return _socket.getNeedClientAuth();
	  }

	  public String[] getSupportedCipherSuites() {
	    return _socket.getSupportedCipherSuites();
	  }

	  public String[] getSupportedProtocols() {
	    return _socket.getSupportedProtocols();
	  }
	    
	  public boolean getUseClientMode() {
	    return _socket.getUseClientMode();
	  }

	  public boolean getWantClientAuth() {
	    return _socket.getWantClientAuth();
	  }

	  public void setEnabledCipherSuites(String[] suites) 
	    throws IllegalArgumentException {
	    _socket.setEnabledCipherSuites(suites);
	  }

	  public void setEnabledProtocols(String[] protocols) 
	    throws IllegalArgumentException {
	    _socket.setEnabledProtocols(protocols);
	  }

	  public void setEnableSessionCreation(boolean flag) {
	    _socket.setEnableSessionCreation(flag);
	  }

	  public void setNeedClientAuth(boolean need) {
	    _socket.setNeedClientAuth(need);
	  }

	  public void setUseClientMode(boolean mode) 
	    throws IllegalArgumentException {
	    _socket.setUseClientMode(mode);
	  }

	  public void setWantClientAuth(boolean want) {
	    _socket.setWantClientAuth(want);
	  }

	  public Socket accept()
	    throws IOException {
	    return _socket.accept();
	  }

	  public void bind(SocketAddress bindpoint)
	    throws IOException{
	    _socket.bind(bindpoint);
	  }

	  public void bind(SocketAddress bindpoint, int backlog)
	    throws IOException{
	    _socket.bind(bindpoint, backlog);
	  }

	  public void close()
	    throws IOException{
	    _socket.close();
	  }

	  public ServerSocketChannel getChannel() {
	    return _socket.getChannel();
	  }
	    
	  public InetAddress getInetAddress() {
	    return _socket.getInetAddress() ;
	  }

	  public int getLocalPort(){
	    return _socket.getLocalPort();
	  }

	  public SocketAddress getLocalSocketAddress(){
	    return _socket.getLocalSocketAddress();
	  }

	  public int getReceiveBufferSize()
	    throws SocketException{
	    return _socket.getReceiveBufferSize();
	  }

	  public boolean getReuseAddress()
	    throws SocketException{
	    return _socket.getReuseAddress();
	  }

	  public int getSoTimeout()
	    throws SocketException, IOException {
	    return _socket.getSoTimeout();
	  }

	  public boolean isBound(){
	    return _socket.isBound();
	  }

	  public boolean isClosed(){
	    return _socket.isClosed();
	  }

	  public void setReceiveBufferSize(int size)
	    throws SocketException{
	    _socket.setReceiveBufferSize(size);
	  }

	  public void setReuseAddress(boolean on)
	    throws SocketException{
	    _socket.setReuseAddress(on);
	  }

	  public void setSoTimeout(int timeout)
	    throws SocketException{
	    _socket.setSoTimeout(timeout);
	  }

	  public String toString(){
	    return _socket.toString();
	  }

	  public int hashCode() {
	    return _socket.hashCode();
	  }
	


	/**
	 * @param args
	 */
	public static void main(String[] args) {
		
		try {
			ServerSocket ss = SSLServerSocketFactory.getDefault().createServerSocket(9999);
			
			Server sss = new Server(ss);
			
			while(true){
				if(sss==null)
					System.out.println("null1");
			SSLSocket s = (SSLSocket)sss.accept();

			if (s == null)
				System.out.println("Got NULL Socket");
			else
				System.out.println("Got Signed Server Socket");
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	

	}

}
