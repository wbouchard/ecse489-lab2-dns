import java.net.DatagramPacket;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DnsManager {
	private static final int FF = 255;
	private static final int FFFF = 65535;
	private static final int ZERO = 0;
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
	
	public enum QType{
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
	}
	
	private static void unsetBit(int index, byte b[]){
		int byteIndex = ((b.length*BYTE_SIZE - 1) - index) / 8;
		index = index % BYTE_SIZE;
		b[byteIndex] = (byte) (b[byteIndex] & ~(1 << index));
	}
	
	public static String bytesToStr(byte[] bs){
		String bytes = "";
		for(byte b : bs){
			bytes += String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
		}
		return bytes;
	}
	
	private static String bytesToStrIP(byte[] bs){
		String bytes = "";
		for(int i=0; i<bs.length-1; i++) {
			bytes += Integer.toUnsignedLong(bs[i] & 0xFF) + ".";
		}
		bytes += Integer.toUnsignedLong(bs[bs.length-1] & 0xFF);
		return bytes;
	}
	
	public static void printOutput() {
		
	}
	
	public static void readDnsAnswer(byte[] answer){
		ByteBuffer dnsBuffer = ByteBuffer.allocate(answer.length);
		byte[] answerCopy = answer;
		dnsBuffer.put(answer);
		//stop writing, now read header
		dnsBuffer.flip();
		byte[] currentBytes = new byte[2];
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		//ID
		long id = getIntFromBytes(currentBytes);
		//QR
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		int qr = (currentBytes[0] & FF) >>> BYTE_SIZE-1;
		//OPCODE
		int opCode = (currentBytes[0] & 120) >>> 3;
		int AA = (currentBytes[0] & 4) >>> 2;
		int TC = (currentBytes[0] & 2) >>> 1;
		int RD = (currentBytes[0] & 1);
		int RA = (currentBytes[1] & 128) >>> BYTE_SIZE-1;
		int Z = (currentBytes[1] & 112) >>> 5;
		int rCode = (currentBytes[1] & 15) >>> 4;
		//qdCount
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		long qdCount = getIntFromBytes(currentBytes);
		//ANCOUNT
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		long anCount = getIntFromBytes(currentBytes);
		
		//NSCOUNT
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		long nsCount = getIntFromBytes(currentBytes);
		//ARCOUNT
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		long arCount = getIntFromBytes(currentBytes);
		
		int currentByteCount = 15;
		//Read names from question
		String nameFieldQuestion = getRData(dnsBuffer, answerCopy);
		//Qtype
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		String qTypeQuestion = bytesToStr(currentBytes);
		//QClass
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		String qClassQuestion = bytesToStr(currentBytes);
		
		//Read answer record
		String nameFieldAnswer = getRData(dnsBuffer, QType.type_CNAME.toString(), answerCopy);
		//Qtype
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		String qTypeAnswer = bytesToStr(currentBytes);
		//QClass
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		String qClassAnswer = bytesToStr(currentBytes);
		//TTL
		currentBytes = new byte[4];
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		long TTL = getIntFromBytes(currentBytes);
		//RDLength
		currentBytes = new byte[2];
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		long rdlLength = getIntFromBytes(currentBytes);
		//RData (for MX type the rData is returned as "Preference:Exchange"
		String rData = getRData(dnsBuffer, qTypeAnswer, answerCopy);
		
		
		// print results
		// did not create a separate method due to the amount of variables managed in this method
		if (anCount != 0) {
			System.out.println("***Answer section (" + anCount + " records)***");
			for (int i = 0; i < anCount; i++) {
				System.out.println("***Record " + i + "***");
			
				if (Integer.parseInt(qClassAnswer) != 1)
					System.out.println("ERROR\t QCLASS value invalid. Expected 1, received " + qClassQuestion);
			
				String authStr;
				if (AA == 1) authStr = "auth";
				else if (AA == 0) authStr = "nonauth";
				else authStr = "ERROR\t Could not resolve authoritative status: " + AA;
				if (rCode == 0) {
					// do nothing
				} else if (rCode == 1) {
					System.out.println("ERROR\t RCODE Format error: the name server was unable to interpret the query");
				} else if (rCode == 2) {
					System.out.println("ERROR\t RCODE Server failure: the server was unable to process this query due to a problem with the name server");
				} else if (rCode == 3) {
					System.out.println("ERROR\t RCODE Name error: the domain name does not exist");
				} else if (rCode == 4) {
					System.out.println("ERROR\t RCODE Unsupported error: the name server does not support this kind of query");
				} else if (rCode == 5) {
					System.out.println("ERROR\t RCODE Refused: the name server refuses to perform the requested operation");
				}
			
				if (qTypeAnswer.equals(QType.type_A.toString())) {
					System.out.format( "IP \t %s \t %d \t %s \n", rData, TTL, authStr);
				} else if (qTypeAnswer.equals(QType.type_CNAME.toString())) {
					System.out.format( "CNAME \t %s \t %d \t %s \n", rData, TTL, authStr);
				} else if (qTypeAnswer.equals(QType.type_MX.toString())) {
					String prefExch[] = rData.split("[:]");
					System.out.format( "MX \t %s \t %s \t %d \t %s \n", prefExch[1], prefExch[0], TTL, authStr);
				} else if (qTypeAnswer.equals(QType.type_NS.toString())) {
					System.out.format( "NS \t %s \t %d \t %s \n", rData, TTL, authStr);
				} else {
					System.out.println("ERROR\t Could not identify query type: " + qTypeAnswer);
				}
			}
		}
		
		if (nsCount != 0) {
			System.out.println("***Additional section (" + arCount + " records)***");
			
			// TODO: parse additional section
		}
		
		if (anCount == 0 && nsCount == 0) System.out.println("NOTFOUND");
	}
	
	public static long getIntFromBytes(byte[] b){
		long unsignedInt = 0;
	    for (int i = 0; i < b.length; i++) {
	    		unsignedInt += b[i] << 8 * (b.length - 1 - i);
	    }
	    return unsignedInt & FFFF;
	}
	
	private static String byteToLetter(byte b) {
		byte letter[] = new byte[1];
		letter[0] = b;
		//Is a letter or number
		if((b > 47 && b < 58) || (b > 96 && b < 123)) {
			return new String(letter);
		} else {
			return b+"";
		}
	}
	
	public static boolean isNumeric(String str)
	{
	  return str.matches("-?\\d+(\\.\\d+)?");
	}
	
	private static String getVariableName(ByteBuffer dnsBuffer, byte[] answerCopy) {
		if(dnsBuffer.remaining()<2) {
			return "";
		}
		byte[] currentBytes = new byte[2];
		dnsBuffer.get(currentBytes, 0, currentBytes.length);
		String rData = "";
		//its a pointer
		if(((currentBytes[0] >> 6) & 3) == 3) {
			int offset = (currentBytes[0] & 63) * 256 + currentBytes[1];
			byte b  = answerCopy[offset];
			offset += 1;
			//while not the 0 character
			boolean firstChar = true;
			while(b != ZERO && offset < answerCopy.length) {
				String letter = byteToLetter(b);
				if(isNumeric(letter) && !firstChar) {
					firstChar = false;
					letter = ".";
				}
				rData += letter;
				b = answerCopy[offset];
				offset += 1;
			}
		} else {
			byte b = currentBytes[0];
			boolean firstLetter = true;
			while(b != ZERO) {
				String letter = byteToLetter(b);
				if(isNumeric(letter)) {
					letter = ".";
				}
				rData += letter;
				if(!firstLetter) {
					if(dnsBuffer.remaining() < 2) {
						return rData;
					} else {
						dnsBuffer.get(currentBytes, 0, currentBytes.length);
					}
					b = currentBytes[0];
				} else {
					b = currentBytes[1];
				}
				firstLetter = !firstLetter;
			}
			if(firstLetter) {
				//Need to reread the last byte later
				dnsBuffer.position(dnsBuffer.position()-1);
			}
		}
		return rData;
	}
	
	private static String getRData(ByteBuffer dnsBuffer, byte[] answerCopy) {
		//Default name matching follows the one used for CNAME
		return getRData(dnsBuffer, QType.type_CNAME.toString(), answerCopy);
		
	}
	
	private static String getRData(ByteBuffer dnsBuffer, String qType, byte[] answerCopy) {
		byte[] currentBytes = new byte[2];
		String rData = "";
		if(qType.equals(QType.type_A.toString())){
			currentBytes = new byte[4];
			dnsBuffer.get(currentBytes, 0, currentBytes.length);
			rData = bytesToStrIP(currentBytes);
			//rData = rData.replaceAll("(.{4})", "$1.");
			//remove last period
			rData = rData.substring(0, rData.length()-1);
		} else if(qType.equals(QType.type_CNAME.toString()) || qType.equals(QType.type_NS.toString())){
			rData = getVariableName(dnsBuffer, answerCopy);
		} else if(qType.equals(QType.type_MX.toString())){
			currentBytes = new byte[2];
			dnsBuffer.get(currentBytes, 0, currentBytes.length);
			long preference = getIntFromBytes(currentBytes);
			//get QNAME
			// for mail server, return rData as Preference:Alias
			rData += String.valueOf(preference);
			rData += ":";
			rData += getVariableName(dnsBuffer, answerCopy);
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
		unsetBit(currentByteCount, currentBytes);
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
		dnsBuffer.put(getQnameBytes(domain));
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
	}
	
	public static byte[] getQnameBytes(String domain){
		domain = convertDomain(domain);
		byte Qname[] = new byte[domain.length()+1];
		for(int i=0; i<domain.length(); i++){
			char letter = domain.charAt(i);
			if(isNumeric(letter+"")) {
				Qname[i] = (byte) Integer.parseInt(letter+"");
			} else {
				Qname[i] = (byte) domain.charAt(i);
			}
		}
		//Signal end of domain
		Qname[Qname.length-1] = 0;
		return Qname;
	}
	
	public static byte[] getBytesBinaryStr(String Qname, int length) {
		ArrayList<Integer> arrayList = new ArrayList<>();
        for(String str : Qname.split("(?<=\\G.{8})"))
            arrayList.add(Integer.parseInt(str, 2));
        ByteBuffer bf = ByteBuffer.allocate(arrayList.size());
        byte[] bytes;
        for(Integer i: arrayList) {
        		bytes = ByteBuffer.allocate(4).putInt(i).array();
        		bf.put(bytes[3]);
        }
        bytes = new byte[bf.position()];
        bf.flip();
        bf.get(bytes, 0, bytes.length);
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
		
		return converted;
	}
}