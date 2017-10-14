import java.net.DatagramPacket;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DnsManager {
	//final static String regex = "(\\|\\t[0-9]*\\t)\\|\\|?(\\t[0-9]*\\t)?\\|";
	final static String FULL = "+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+" + System.lineSeparator();
	final static String HALF = System.lineSeparator() + "+--+--+--+--+--+--+--+--+"+System.lineSeparator();
	private static final int BYTE_SIZE = 8;
	
	private enum QClass{
		internetAddr {
			@Override
		    public String toString() {
		        return "0000000000000001";
		    }
		 }
	}
	
	private enum QType{
		type_A {
		      public String toString() {
		          return "0000000000000001";
		      }
		 },
		 type_NS {
		      public String toString() {
		    	  return "0000000000000010";
		      }
		 },
		 type_MX {
		      public String toString() {
		    	  return "0000000000001111";
		      }
		 },
		 type_CNAME {
		      public String toString() {
		    	  return "0000000000000101";
		      }
		 }
	}
	
	private static void setBits(int start, int end, byte[] b){
		for(int i=start; i>=end; i--){
			setBit(i, b);
		}
	}
	
	private static void unsetBits(int start, int end, byte[] b){
		for(int i=start; i>=end; i--){
			unsetBit(i, b);
		}
	}
	
	private static void setBit(int index, byte b[]){
		//arrays are [0,1,2,...,15], but bits are [15,14,13,...0]
		int byteIndex = ((b.length*BYTE_SIZE - 1) - index) / 8;
		index = index % BYTE_SIZE;
		b[byteIndex] = (byte) (b[byteIndex] | (1 << index));
		//String s1 = String.format("%8s", Integer.toBinaryString(b[byteIndex] & 0xFF)).replace(' ', '0');
    	//System.out.println(s1);
	}
	
	private static void unsetBit(int index, byte b[]){
		int byteIndex = ((b.length*BYTE_SIZE - 1) - index) / 8;
		index = index % BYTE_SIZE;
		b[byteIndex] = (byte) (b[byteIndex] & ~(1 << index));
		//String s1 = String.format("%8s", Integer.toBinaryString(b[byteIndex] & 0xFF)).replace(' ', '0');
    	//System.out.println(s1);
	}
	
	private static String bytesToStr(byte[] bs){
		String bytes = "";
		for(byte b : bs){
			bytes += String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
		}
		return bytes;
	}
	
	public static void readDnsAnswer(byte[] answer){
		ByteBuffer dnsBuffer = ByteBuffer.allocate(answer.length);
		dnsBuffer.put(answer);
		byte[] currentBytes = new byte[2];
		int currentByteCount = 15;
		//stop writing, now read
		dnsBuffer.flip();
		//Read names
		//Qtype
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		String Qtype = bytesToStr(currentBytes);
		//QClass
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		String QClass = bytesToStr(currentBytes);
		//TTL
		currentBytes = new byte[4];
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		long TTL = getIntFromBytes(currentBytes);
		//RDLength
		currentBytes = new byte[2];
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		long rdlLength = getIntFromBytes(currentBytes);
		//RData
		String rData = getRData(dnsBuffer, Qtype);
	}
	
	public static long getIntFromBytes(byte[] b){
		long unsignedInt = 0;
	    for (int i = 0; i < b.length; i++) {
	    	unsignedInt += b[i] << 8 * (b.length - 1 - i);
	    }
	    return unsignedInt;
	}
	
	private static String getRData(ByteBuffer dnsBuffer, String qType) {
		byte[] currentBytes;
		String rData = "";
		if(qType.equals(QType.type_A.toString())){
			currentBytes = new byte[4];
			dnsBuffer.get(currentBytes, 0, currentBytes.length);
			rData = bytesToStr(currentBytes);
			rData = rData.replaceAll("(.{4})", "$1.");
			//remove last period
			rData = rData.substring(0, rData.length()-1);
		} else if(qType.equals(QType.type_CNAME.toString())){
			//get
		} else if(qType.equals(QType.type_MX.toString())){
			currentBytes = new byte[2];
			dnsBuffer.get(currentBytes, 0, currentBytes.length);
			long preference = getIntFromBytes(currentBytes);
			//get QNAME
		} else if(qType.equals(QType.type_NS.toString())){
			
		}
		return rData;
	}

	public static byte[] getDnsQuestion(String domain, boolean mailServer, boolean nameServer){
		ByteBuffer dnsBuffer = ByteBuffer.allocate(1024);
		dnsBuffer.clear();
		int currentByteCount = 15;
		SecureRandom sr = new SecureRandom();
		byte[] rndId = new byte[2];
		sr.nextBytes(rndId);
		new SecureRandom().nextBytes(rndId);
		//id
		dnsBuffer.put(rndId);
		//QR to Z-code
		byte currentBytes[] = new byte[2];
		//qr
		setBit(currentByteCount, currentBytes);
		currentByteCount--;
		//OPCODE
		unsetBits(currentByteCount, currentByteCount-3, currentBytes);
		currentByteCount-=4;
		//AA
		unsetBit(currentByteCount, currentBytes);
		currentByteCount--;
		//TC
		if(convertDomain(domain).length() > 63){
			setBit(currentByteCount, currentBytes);
		} else{
			unsetBit(currentByteCount, currentBytes);
		}
		currentByteCount--;
		//RD desire recursion
		setBit(currentByteCount, currentBytes);
		currentByteCount--;
		//RA
		unsetBit(currentByteCount, currentBytes);
		currentByteCount--;
		//Z
		unsetBits(currentByteCount, currentByteCount-2, currentBytes);
		currentByteCount-=3;
		//RCODE
		unsetBits(currentByteCount, currentByteCount-3, currentBytes);
		currentByteCount -= 4;
		//Add to buffer
		dnsBuffer.put(currentBytes);
		currentBytes = new byte[2];
		//QDCOUNT always 1
		setBit(0, currentBytes);
		dnsBuffer.put(currentBytes);
		currentBytes = new byte[2];
		//ANCOUNT  (NOT FOR QUESTION)
		unsetBits(15, 0, currentBytes);
		dnsBuffer.put(currentBytes);
		currentBytes = new byte[2];
		//NSCOUNT  (NOT FOR QUESTION)
		unsetBits(15, 0, currentBytes);
		dnsBuffer.put(currentBytes);
		currentBytes = new byte[2];
		//ARCOUNT (NOT FOR QUESTION)
		unsetBits(15, 0, currentBytes);
		dnsBuffer.put(currentBytes);
		currentBytes = new byte[2];
		//Qname
		dnsBuffer.put(getQname(domain));
		//Qtype
		if(mailServer){
			dnsBuffer.put(getBytesBinaryStr(QType.type_MX.toString(), 16));
		} else if(nameServer){
			dnsBuffer.put(getBytesBinaryStr(QType.type_NS.toString(), 16));
		} else{
			dnsBuffer.put(getBytesBinaryStr(QType.type_A.toString(), 16));
		}
		//QClass
		dnsBuffer.put(getBytesBinaryStr(QClass.internetAddr.toString(), 16));
		return Arrays.copyOfRange(dnsBuffer.array(), 0, dnsBuffer.position());
		/*dnsQuestion += addField(id.toString());
		dnsQuestion += getQname(domain);
		if(mailServer){
			dnsQuestion += addField(QType.type_MX.toString());
		} else if(nameServer){
			dnsQuestion += addField(QType.type_NS.toString());
		}
		dnsQuestion += addField(QClass.internetAddr.toString());
		System.out.println(dnsQuestion);*/
	}
	
	private static String addField(String field){
		return String.format("|\t\t%s\t\t|\n%s", field, FULL);
	}
	
	private static byte[] getQname(String domain){
		domain = convertDomain(domain);
		byte Qname[] = new byte[domain.length()];
		for(int i=0; i<domain.length(); i++){
			char c = domain.charAt(i);
			Qname[i] = getBytesBinaryStr(getAscii(c), BYTE_SIZE)[0];
		}
		return Qname;
		/*String Qname = FULL;
		Qname += "|";
		boolean second = false;
		for(int i=0; i<domain.length(); i++){
			char c = domain.charAt(i);
			Qname += addCharQname(c);
			if(second && i != domain.length()-1){
				Qname += "\n" + FULL + "|";
			}
			second = !second;
		}
		if(!second){
			Qname += "\n" + FULL;
		}
		if(domain.length() % 2 != 0){
			Qname += "\t\t\t|";
			Qname += "\n" + FULL;
		}
		//System.out.println(Qname);
		return Qname;*/
	}
	
	private static byte[] getBytesBinaryStr(String Qname, int length) {
		//short binShort = Short.parseShort(Qname, 2);
		int numberOfBytes = length % 8 == 0 ? length/8 : length/8 + 1;
		byte bytes[] = new byte[numberOfBytes];
		for(int i=0; i<numberOfBytes; i++){
			bytes[i] = Byte.parseByte(Qname.substring(i, i+8), 2);
		}
		//ByteBuffer bytes = ByteBuffer.allocate(numberOfBytes).put(Byte.parseByte(Qname, 2));
		return bytes;
	}

	private static String convertDomain(String domain) {
		String converted = "";
		int end = 0;
		int counter = 0;
		for(char c : domain.toCharArray()){
			if(c != '.'){
				end++;
			} else{
				converted += end + domain.substring(counter - end, counter);
				end = 0;
			}
			counter++;
		}
		converted += end + domain.substring(counter - end, counter);
		
		//Signal domain name end
		converted += "0";
		return converted;
	}


	private static String getAscii(char c){
		return String.format("%08d", Integer.parseInt(Integer.toBinaryString((int) c)));
	}
	
}