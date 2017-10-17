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
			rData = rData.replaceAll("(.{4})", "$1.");
			//remove last period
			rData = rData.substring(0, rData.length()-1);
		} else if(qType.equals(QType.type_CNAME.toString()) || qType.equals(QType.type_NS.toString())){
			rData = getVariableName(dnsBuffer, answerCopy);
		} else if(qType.equals(QType.type_MX.toString())){
			currentBytes = new byte[2];
			dnsBuffer.get(currentBytes, 0, currentBytes.length);
			long preference = getIntFromBytes(currentBytes);
			//get QNAME
			rData = String.format("%l:%s", preference, getVariableName(dnsBuffer, answerCopy));
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
			//char c = domain.charAt(i);
			//Qname[i] = getBytesBinaryStr(getAscii(c), BYTE_SIZE)[0];
		}
		//Signal end of domain
		Qname[Qname.length-1] = 0;
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
		
		//short binShort = Short.parseShort(Qname, 2);
		/*int numberOfBytes = length % 8 == 0 ? length/8 : length/8 + 1;
		byte bytes[] = new byte[numberOfBytes];
		for(int i=0; i<numberOfBytes; i++){
			bytes[i] = Byte.parseByte(Qname.substring(i, i+8), 2);
		}*/
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
		
		return converted;
	}


	private static String getAscii(char c){
		//return (""+c).getBytes(Charset.forName("UTF-8"));
		return String.format("%08d", Integer.parseInt(Integer.toBinaryString((int) c)));
	}
	
}