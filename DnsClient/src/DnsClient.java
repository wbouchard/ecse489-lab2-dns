import org.apache.commons.cli.*;

public class DnsClient {

	public static void main(String[] args) {
		
		Options options = getOptions();
        
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("utility-name", options);

            System.exit(1);
            return;
        }
        String timeout = cmd.getOptionValue("timeout", "5");
        String max_retries = cmd.getOptionValue("max-retries", "3");
        String port = cmd.getOptionValue("port", "53");
        boolean mailServer = cmd.hasOption("mailServer");
        boolean nameServer = cmd.hasOption("nameServer");
        String[] leftoverArgs = cmd.getArgs();
        if(leftoverArgs.length != 2 || (mailServer && nameServer)){
        	System.out.println("Required command format: \"java DnsClient [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name\"");
        	System.exit(1);
            return;
        }
        
        // input argument parsing and error handling
        int t = 0;
        int mr = 0;
        int p = 0;
        try {
        	t = Integer.parseInt(timeout);
        } catch (NumberFormatException e) {
        	System.out.println("ERROR\t Invalid argument for timeout; please enter an integer.");
        	System.out.println("Required command format: \"java DnsClient [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name\"");
        	System.exit(1);
        	return;
        }
        try {
        	mr = Integer.parseInt(max_retries);
        } catch (NumberFormatException e) {
        	System.out.println("ERROR\t Invalid argument for max retries; please enter an integer.");
        	System.out.println("Required command format: \"java DnsClient [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name\"");
        	System.exit(1);
        	return;
        }
        try {
        	p = Integer.parseInt(port);
        	if (p != 53)
        		System.out.println("WARNING\t ** Consider using port 53, the official port for DNS requests.");
        } catch (NumberFormatException e) {
        	System.out.println("ERROR\t Invalid argument for port number; please enter an integer.");
        	System.out.println("Required command format: \"java DnsClient [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name\"");
        	System.exit(1);
        	return;
        }
        if (t < 0 || mr < 0 || p < 0) {
        	System.out.println("ERROR\t Please enter positive integer values for the timeout, max retries, and/or port number.");
        	System.out.println("Required command format: \"java DnsClient [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name\"");
        	System.exit(1);
        	return;
        }


        String server = leftoverArgs[0];
        if (server.charAt(0) != '@') {
        	System.out.println("ERROR\t Invalid argument for IP address; please add @ to the beginning of the IP address.");
        	System.out.println("Required command format: \"java DnsClient [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name\"");
        	System.exit(1);
        	return;
        }
        server = server.substring(1); // remove @ before the ip address given in command line args
        
        // tokenize given IP address for error handling
        String[] tokens = server.split("[.]");
        boolean invalid = false;
        if (tokens.length != 4)
        	invalid = true;
        else {
        	for (int i = 0; i < tokens.length; i++) {
        		try {
            		if (Integer.parseInt(tokens[i]) > 255 || Integer.parseInt(tokens[i]) < 0) {
            			invalid = true;
            			break;
            		}
        		} catch (NumberFormatException e) {
        			invalid = true;
        		}
        	}
        }
		if(invalid == true) {
			System.out.println("ERROR\t Invalid argument for IP address; please follow the IPV4 format @XXX.XXX.XXX.XXX, where each XXX value is an integer 0 and 255.");
			System.out.println("Required command format: \"java DnsClient [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name\"");
			System.exit(1);
			return;
		}
        
        String name = leftoverArgs[1];
        if (name.indexOf('.') == -1) {
        	System.out.println("ERROR\t Invalid argument for queried name; please ensure that there is a period (.) in your address.");
        	System.out.println("Required command format: \"java DnsClient [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name\"");
        	System.exit(1);
        	return;
        }
        
        //Print initial output using arguments
        System.out.println(String.format("DnsClient sending request for %s", name));
        System.out.println(String.format("Server: %s:%d", server, p));
        String requestType = "A";
        if(mailServer || nameServer){
        	requestType = mailServer ? "MX" : "NS";
        }
        System.out.println(String.format("Request type: %s", requestType));
        
        UDPClientSocket cs = new UDPClientSocket(t, mr, p, server, name, mailServer, nameServer);
        cs.sendDnsRequest();
	}
	
	private static Options getOptions(){
		Options options = new Options();
        Option timeout = new Option("t", "timeout", true, "Gives how long to wait, in seconds, before retransmitting an unanswered query. Default value: 5");
        options.addOption(timeout);

        Option maxRetries = new Option("r", "max-retries", true, "Maximum number of times to retransmit an unanswered query before giving up. Default value: 3");
        options.addOption(maxRetries);
        
        Option port = new Option("p", "port", true, "The UDP port number of the DNS server. Default value: 53");
        options.addOption(port);
        
        Option flagMailServer = new Option("mx", "mailServer", false, "Indicates whether to send a MX (mail server)");
        options.addOption(flagMailServer);
        
        Option flagNameServer = new Option("ns", "nameServer", false, "Indicates whether to send a NS (name server)");	
        options.addOption(flagNameServer);
        
        return options;
	}

}
