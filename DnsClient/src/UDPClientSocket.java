import java.io.*;
import java.net.*;

public class UDPClientSocket {

	int timeout;
	int max_retries;
	int port;
	String server;
	String name;
	byte[] dns_request;
	boolean mailServer;
	boolean nameServer;
	
	// constructor
	public UDPClientSocket(int timeout, int max_retries, int port, String server, String name, boolean mailServer, boolean nameServer) {
		this.timeout = timeout;
		this.max_retries = max_retries;
		this.port = port;
		this.server = server;
		this.name = name;
		this.mailServer = mailServer;
		this.nameServer = nameServer;
	}
	
	// create client socket that sends a dns request and waits for an answer
	public void sendDnsRequest() {
		try {
			// create client socket
			DatagramSocket clientsocket = new DatagramSocket();
			
			byte[] rcvData = new byte[1024];
			byte[] sendData = new byte[1024];
			
			int retries = 0;
			boolean receivedResponse = false;
			
			// wait on receive for this amount of time. socket throws exception if nothing was received.
			clientsocket.setSoTimeout(timeout * 1000);
			
			// used to calculate time it took to receive an answer (uses JVM time)
			float startTime = System.nanoTime();
			
			// limit number of times the while loop is entered according to max_retries arg
			while (retries < max_retries && !receivedResponse) {
				// generate new dns request each time to create a new random ID
		        byte[] dns_request = DnsManager.createDnsQuery(name, mailServer, nameServer);
				sendData = dns_request;
				byte[] ipAddr = convertIpAddrToByteArray(server);
				if(ipAddr == null) {
					return;
				}
				InetAddress server_ina = InetAddress.getByAddress(ipAddr);
				DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, server_ina, port);
				
				clientsocket.send(sendPacket);
				System.out.format("Client\t Sent DNS request to %s:%d [retries = %d]\n", server, port, retries);
					
				// receive
				DatagramPacket rcvPacket = new DatagramPacket(rcvData, rcvData.length);
				try {
					clientsocket.receive(rcvPacket);
					// no exception was raised -> received something
					receivedResponse = true;
					rcvData = rcvPacket.getData();
				} catch (SocketTimeoutException e) {
					retries++;
					if (retries == max_retries) 
						System.out.println("ERROR\t Reached maximum number of retries: " + retries);
				}
			}
			
			if (receivedResponse) {
				float endTime = System.nanoTime();
				float queryTime = (endTime - startTime) / 1000000000;
				System.out.println("Client\t Response received after " + queryTime + " seconds. (" + retries + " retries)");
				DnsManager.readDnsAnswer(rcvData);
			}
			
			// close client socket when data was sent and received
			clientsocket.close();
			System.out.println("Client\t Closed socket successfully. Exiting...");
		} catch (IOException e) {
			System.out.println("ERROR\t Could not create client socket: " + e.getMessage());
		}
	}
	
	// separate an IP address into 4 tokens, and convert those to a byte representation
	public static byte[] convertIpAddrToByteArray(String ipAddr) {
		byte[] byteaddr = null;
			String[] tokens = ipAddr.split("[.]");
			byteaddr = new byte[4];
			for (int i = 0; i < byteaddr.length; i++) {
				byteaddr[i] = (byte)Integer.parseInt(tokens[i]);
				
				// move byte back to int to test conversion
				//System.out.println(i + " : " + Byte.toUnsignedInt(byteaddr[i]));
			}
		return byteaddr;
	}
}
