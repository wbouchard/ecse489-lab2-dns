import org.apache.commons.cli.*;

public class Main {

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
        String maxRetries = cmd.getOptionValue("max-retries", "3");
        String port = cmd.getOptionValue("port", "3");
        boolean mailServer = cmd.hasOption("mailServer");
        boolean nameServer = cmd.hasOption("nameServer");
        String[] leftoverArgs = cmd.getArgs();
        if(leftoverArgs.length != 2 || (mailServer && nameServer)){
        	System.out.println("Required command format: \"java DnsClient [-t timeout] [-r max-retries] [-p port] [-mx|-ns] @server name\"");
        	System.exit(1);
            return;
        }
        String server = leftoverArgs[0];
        String name = leftoverArgs[1];
        
        //Print request
        System.out.println(String.format("DnsClient sending request for %s", name));
        System.out.println(String.format("Server: %s", server));
        String requestType = "A";
        if(mailServer || nameServer){
        	requestType = mailServer ? "MX" : "NS";
        }
        System.out.println(String.format("Request type: %s", requestType));
        
        byte[] dnsQuestion = DnsManager.getDnsQuestion(name, mailServer, nameServer);
        /*for(int i=0; i<b.length; i++){
        	String s1 = String.format("%8s", Integer.toBinaryString(b[i] & 0xFF)).replace(' ', '0');
        	System.out.println(s1);
        }*/
        //System.out.print(timeout + " " + nameServer + " " + mailServer + " " + server + " " + name);
	
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
