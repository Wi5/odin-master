package net.floodlightcontroller.odin.applications;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Arrays;
import java.util.Scanner;
import java.io.*;

import net.floodlightcontroller.odin.master.OdinApplication;
import net.floodlightcontroller.odin.master.OdinClient;
import net.floodlightcontroller.util.MACAddress;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;

public class DemoStatistics extends OdinApplication {

  // IMPORTANT: this application only works if all the agents in the
  //poolfile are activated before the end of the INITIAL_INTERVAL.
  // Otherwise, the application looks for an object that does not exist
  //and gets stopped

  // this interval is for allowing the agents to connect to the controller
  private final int INITIAL_INTERVAL = 30000; // in ms
  
  private Scanner in = new Scanner(System.in);
  
  private int option;

  HashSet<OdinClient> clients;
  Map<MACAddress, Map<String, String>> vals_tx;
  Map<MACAddress, Map<String, String>> vals_rx;
  int result; // Result for scanning
  // Scanning agents
  Map<InetAddress, Integer> scanningAgents = new HashMap<InetAddress, Integer> ();
  // SSID to scan
  String SCANNED_SSID = "";
  int[] channels = null;
  int num_channels = 0;
  int num_agents = 0;
  String[][] vals_rx_value = null;
  Map<MACAddress, Double[]> rssiData = new HashMap<MACAddress, Double[]> (); // Map to store RSSI for each STA in all APs
  
  InetAddress nullAddr = null;
  InetAddress vipAPAddr = null;

  @Override
  public void run() {
    try {
      Thread.sleep(INITIAL_INTERVAL);
    } catch (InterruptedException e) {
	  e.printStackTrace();
    }
    
    InetAddress[] agents = getAgents().toArray(new InetAddress[0]);
    
    int num_agents = agents.length;
    try {
    		System.out.println("[DemoStatistics] =============================================================");
    		System.out.println("[DemoStatistics] ===================LANZANDO HTTP SERVER======================");
        HttpServer server = HttpServer.create(new InetSocketAddress(8000), 0);
        server.createContext("/test", new MyHandler());
        server.setExecutor(null); // creates a default executor
        server.start();
    } catch (Exception  e) {
	      e.printStackTrace();
	    }

    while (true) {
      try {
        Thread.sleep(100);

		System.out.println("[DemoStatistics] =============================================================");
		System.out.println("[DemoStatistics] ==============Internal and external Statistics===============");
		System.out.println("[DemoStatistics]");

	    // for each Agent
	    for (InetAddress agentAddr: agents) {
	      System.out.println("[DemoStatistics] Agent: " + agentAddr);
	      clients = new HashSet<OdinClient>(getClientsFromAgent(agentAddr));
	      if(clients.size()!=0){
	        System.out.println("[DemoStatistics] \tClients:");
	        for (OdinClient oc: clients) {
	          System.out.println("[DemoStatistics] \t\t"+oc.getIpAddress().getHostAddress());
            }
          }else{
            System.out.println("[DemoStatistics] \tNo clients associated");
          }
        }
        System.out.println("[DemoStatistics] =============================================================");
        System.out.println("[DemoStatistics] 1) Internal statistics");
        System.out.println("[DemoStatistics] 2) External statistics");
        System.out.println("[DemoStatistics] 3) Active scanning (Matrix of \"distance in dBs\")");
        System.out.println("[DemoStatistics] 4) Passive scanning (Matrix of RSSI heard from STAs)");
        System.out.println("[DemoStatistics] =============================================================");
        System.out.print("\tSelect option to continue: ");
        option = promptKey();
        int agent_index = 0;
        switch (option) {
            case 1:  System.out.println("[DemoStatistics] =======Internal statistics=======");
                     // for each Agent
                     agent_index = 0;
                     for (InetAddress agentAddr: agents) {
                       
                       System.out.println("[DemoStatistics] Agent ["+agent_index+"]: " + agentAddr);
                       System.out.println("[DemoStatistics] \tTxpower: " + getTxPowerFromAgent(agentAddr)+" dBm");
                       System.out.println("[DemoStatistics] \tChannel: " + getChannelFromAgent(agentAddr));
                       System.out.println("[DemoStatistics] \tLast heard: " + (System.currentTimeMillis()-getLastHeardFromAgent(agentAddr)) + " ms ago");
                       System.out.println("[DemoStatistics]");
                       agent_index++;
                     
                     }
                     System.out.print("\tSelect agent [0-"+(agent_index-1)+"]: ");// FIXME: Assuming no mistake, key in range
                     agent_index = promptKey();
                     clients = new HashSet<OdinClient>(getClientsFromAgent(agents[agent_index]));
                     if(clients.size()==0){
                       System.out.println("[DemoStatistics] No clients associated");
                       break;
                     }
                     vals_tx = getTxStatsFromAgent(agents[agent_index]);
                     vals_rx = getRxStatsFromAgent(agents[agent_index]);
                     System.out.println("[DemoStatistics] =============================================================");
                     for (OdinClient oc: clients) {  // all the clients currently associated
                       // for each STA associated to the Agent
                       System.out.println("[DemoStatistics] <<<<<<<<< Rx statistics >>>>>>>>>");
                       for (Entry<MACAddress, Map<String, String>> vals_entry_rx: vals_rx.entrySet()) {

                         MACAddress staHwAddr = vals_entry_rx.getKey();
                         if (oc.getMacAddress().equals(staHwAddr) && oc.getIpAddress() != null && !oc.getIpAddress().getHostAddress().equals("0.0.0.0")) {
                           System.out.println("\tUplink station MAC: " + staHwAddr + " IP: " + oc.getIpAddress().getHostAddress());
                           System.out.println("\t\tnum packets: " + vals_entry_rx.getValue().get("packets"));
                           System.out.println("\t\tavg rate: " + vals_entry_rx.getValue().get("avg_rate") + " kbps");
                           System.out.println("\t\tavg signal: " + vals_entry_rx.getValue().get("avg_signal") + " dBm");
                           System.out.println("\t\tavg length: " + vals_entry_rx.getValue().get("avg_len_pkt") + " bytes");
                           System.out.println("\t\tair time: " + vals_entry_rx.getValue().get("air_time") + " ms");			
                           System.out.println("\t\tinit time: " + vals_entry_rx.getValue().get("first_received") + " sec");
                           System.out.println("\t\tend time: " + vals_entry_rx.getValue().get("last_received") + " sec");
                           System.out.println("");
                         }
                       }
                       System.out.println("[DemoStatistics] <<<<<<<<< Tx statistics >>>>>>>>>");
                       // for each STA associated to the Agent
                       for (Entry<MACAddress, Map<String, String>> vals_entry_tx: vals_tx.entrySet()) {
                         MACAddress staHwAddr = vals_entry_tx.getKey();
                         if (oc.getMacAddress().equals(staHwAddr) && oc.getIpAddress() != null && !oc.getIpAddress().getHostAddress().equals("0.0.0.0")) {
                           System.out.println("\tDownlink station MAC: " + staHwAddr + " IP: " + oc.getIpAddress().getHostAddress());
                           System.out.println("\t\tnum packets: " + vals_entry_tx.getValue().get("packets"));
                           System.out.println("\t\tavg rate: " + vals_entry_tx.getValue().get("avg_rate") + " kbps");
                           System.out.println("\t\tavg signal: " + vals_entry_tx.getValue().get("avg_signal") + " dBm");
                           System.out.println("\t\tavg length: " + vals_entry_tx.getValue().get("avg_len_pkt") + " bytes");
                           System.out.println("\t\tair time: " + vals_entry_tx.getValue().get("air_time") + " ms");			
                           System.out.println("\t\tinit time: " + vals_entry_tx.getValue().get("first_received") + " sec");
                           System.out.println("\t\tend time: " + vals_entry_tx.getValue().get("last_received") + " sec");
                           System.out.println("");
                         }
                       }
                     }
                     System.out.println("[DemoStatistics] =============================================================");
                     break;
            case 2:  System.out.println("[DemoStatistics] =======External statistics=======");//channel and agent ¿? stas or ap??¿
                     agent_index = 0;
                     int channel = 0;
                     int scanning_interval = 0;

                     for (InetAddress agentAddr: agents) {
	  
                       System.out.println("[DemoStatistics] Agent ["+agent_index+"]: " + agentAddr);
                       System.out.println("[DemoStatistics]");
                       agent_index++;
                     
                     }
                     System.out.print("\tSelect agent [0-"+(agent_index-1)+"]: ");// FIXME: Assuming no mistake, key in range
                     agent_index = promptKey();
                     System.out.print("\tSelect channel to scan [1-11]: ");// FIXME: Assuming no mistake, channel in range
                     channel = promptKey();
                     System.out.print("\tSelect time to scan (msec): ");// FIXME: Assuming no mistake
                     scanning_interval = promptKey();
                     result = requestScannedStationsStatsFromAgent(agents[agent_index], channel, "*");
                     System.out.println("[DemoStatistics] <<<<< Scanning in channel "+channel+" >>>>>>");
                     try {
                       Thread.sleep(scanning_interval);
                     }catch (InterruptedException e) {
                       e.printStackTrace();
                     }
                     if (result == 0) {
					   System.out.println("[DemoStatistics] Agent BUSY during scanning operation");
					   break;
                     }
                     clients = new HashSet<OdinClient>(getClientsFromAgent(agents[agent_index]));
					 
					 /*if(clients.size()==0){
                       System.out.println("[DemoStatistics] No clients associated");
                       break;
                     }*/
					 
                     Map<MACAddress, Map<String, String>> vals_rx = getScannedStationsStatsFromAgent(agents[agent_index], "*");
                     // for each STA scanned by the Agent
                     for (Entry<MACAddress, Map<String, String>> vals_entry_rx: vals_rx.entrySet()) {
                     // NOTE: the clients currently scanned MAY NOT be the same as the clients who have been associated		
					   MACAddress staHwAddr = vals_entry_rx.getKey();
					   boolean isWi5Sta = false;
					   boolean isWi5Lvap= false;
                       System.out.println("\tStation MAC: " + staHwAddr);
                       System.out.println("\t\tnum packets: " + vals_entry_rx.getValue().get("packets"));
					   System.out.println("\t\tavg rate: " + vals_entry_rx.getValue().get("avg_rate") + " kbps");
					   System.out.println("\t\tavg signal: " + vals_entry_rx.getValue().get("avg_signal") + " dBm");
					   System.out.println("\t\tavg length: " + vals_entry_rx.getValue().get("avg_len_pkt") + " bytes");
					   System.out.println("\t\tair time: " + vals_entry_rx.getValue().get("air_time") + " ms");						
					   System.out.println("\t\tinit time: " + vals_entry_rx.getValue().get("first_received") + " sec");
					   System.out.println("\t\tend time: " + vals_entry_rx.getValue().get("last_received") + " sec");
					
					   for (OdinClient oc: clients) {  // all the clients currently associated							
						 if (oc.getMacAddress().equals(staHwAddr)) {
                           System.out.println("\t\tAP of client: " + oc.getLvap().getAgent().getIpAddress());
                           System.out.println("\t\tChannel of AP: " + getChannelFromAgent(oc.getLvap().getAgent().getIpAddress()));
                           System.out.println("\t\tCode: Wi-5 STA");
                           System.out.println("");
                           isWi5Sta = true;
                           break;
						 }
						 if (oc.getLvap().getBssid().equals(staHwAddr)){
                           System.out.println("\t\tAP of client: " + oc.getLvap().getAgent().getIpAddress());
                           System.out.println("\t\tChannel of AP: " + getChannelFromAgent(oc.getLvap().getAgent().getIpAddress()));
                           System.out.println("\t\tCode: Wi-5 LVAP");		
                           System.out.println("");
                           isWi5Lvap = true;
                           break;
						 }
                       }
					   if (isWi5Sta) {
                         continue;
					   }
					   if (isWi5Lvap) {
                         continue;
					   }		
					   System.out.println("\t\tAP of client: unknown");
					   System.out.println("\t\tChannel of AP: unknown");
					   if(vals_entry_rx.getValue().get("equipment").equals("AP")){
                         System.out.println("\t\tCode: non-Wi-5 AP");
					   }else{
                         System.out.println("\t\tCode: non-Wi-5 STA");
					   }
					   System.out.println("");		
				     }
                     System.out.println("[DemoStatistics] =============================================================");
                     break;
            case 3:  System.out.println("[DemoStatistics] ========Active scanning (Matrix of \"distance in dBs\")========");

                     SCANNED_SSID = "odin_init";

                     // Matrix
                     String matrix = "";
                     String avg_dB = "";
            
                     for (InetAddress beaconAgentAddr: getAgents()) {
                        scanningAgents.clear();
                        System.out.println("[DemoStatistics] Agent to send measurement beacon: " + beaconAgentAddr);	
			
                        // For each Agent
                        for (InetAddress agentAddr: getAgents()) {
                            if (agentAddr != beaconAgentAddr) {
                                // Request distances
                                result = requestScannedStationsStatsFromAgent(agentAddr, 6, SCANNED_SSID);		
                                scanningAgents.put(agentAddr, result);
                            }
                        }					
				
                        // Request to send measurement beacon
                        if (requestSendMesurementBeaconFromAgent(beaconAgentAddr, 6, SCANNED_SSID) == 0) {
                            System.out.println("[DemoStatistics] Agent BUSY during measurement beacon operation");
                            continue;				
                        }

                        try {
                            Thread.sleep(6000);
                        } 
                        catch (InterruptedException e) {
							e.printStackTrace();
                        }
			
                        // Stop sending meesurement beacon
                        stopSendMesurementBeaconFromAgent(beaconAgentAddr);
			
                        matrix = matrix + beaconAgentAddr.toString().substring(1);

                        for (InetAddress agentAddr: getAgents()) {			
                            if (agentAddr != beaconAgentAddr) {

                                // Reception distances
                                if (scanningAgents.get(agentAddr) == 0) {
                                    System.out.println("[DemoStatistics] Agent BUSY during scanning operation");
                                    continue;				
                                }		
                                vals_rx = getScannedStationsStatsFromAgent(agentAddr,SCANNED_SSID);

                                // for each STA scanned by the Agent
                                for (Entry<MACAddress, Map<String, String>> vals_entry_rx: vals_rx.entrySet()) {
                                // NOTE: the clients currently scanned MAY NOT be the same as the clients who have been associated		
                                    MACAddress APHwAddr = vals_entry_rx.getKey();
                                    avg_dB = vals_entry_rx.getValue().get("avg_signal");
                                    System.out.println("\tAP MAC: " + APHwAddr);
                                    System.out.println("\tavg signal: " + avg_dB + " dBm");
                                    if(avg_dB.length()>6){
                                        matrix = matrix + "\t" + avg_dB.substring(0,6) + " dBm";
                                    }else{
                                        matrix = matrix + "\t" + avg_dB + " dBm   ";
                                    }
                                }

                            }else{
                                matrix = matrix + "\t----------";
                            }   
                        }
                        matrix = matrix + "\n";
                     }
                     //Print matrix
                     System.out.println("[DemoStatistics] =============================================================\n");
                     System.out.println(matrix);            
                     System.out.println("[DemoStatistics] =============================================================");
                     break;
            case 4:  System.out.println("[DemoStatistics] ==============Passive scanning (Matrix of RSSI)==============");
                     SCANNED_SSID = "*";
                     channels = new int[num_agents]; // Array to store the channels in use
                     int[] channelsAux = new int[num_agents];
                     String showAPsLine = "[DemoStatistics] ";
    
                     try { // Create Ip to compare with clients not assigned
                        nullAddr = InetAddress.getByName("0.0.0.0");
                     } catch (UnknownHostException e) {
                        e.printStackTrace();
                     }
                     int ind_aux = 0;
                     num_channels = 0;
                     // Get channels from APs, assuming there is no change in all operation, if already in array->0
                     for (InetAddress agentAddr: agents) {
                       
                       String hostIP = agentAddr.getHostAddress(); // Build line for user interface
                       showAPsLine = showAPsLine + "\033[0;1m[ AP" + hostIP.substring(hostIP.lastIndexOf('.')+1,hostIP.length()) + " ]";

                       int chann = getChannelFromAgent(agentAddr);
                       Arrays.sort(channelsAux);
                    
                       if(Arrays.binarySearch(channelsAux, chann) < 0){// if already in array, not necessary to add it
                         channelsAux[num_channels] = chann;
                         channels[num_channels] = chann;
                       }
                       System.out.println("[DemoStatistics] AP " + agentAddr + " in channel: " + chann);
                       num_channels++;
                       ind_aux++;
                       
                       vals_rx_value = new String[num_channels][num_agents]; // Matrix to store the results from agents
                       Map<MACAddress, Double[]> rssiData = new HashMap<MACAddress, Double[]> (); // Map to store RSSI for each STA in all APs
                       Map<MACAddress, Long> handoffDate = new HashMap<MACAddress, Long> (); // Map to store last handoff for each STA FIXME: Maybe create struct

                       Map<MACAddress, Double[]> ffData = new HashMap<MACAddress, Double[]> (); // Map to store Throughput available for each STA in all APs
                     }
                     clients = new HashSet<OdinClient>(getClients());

                     int num_clients = clients.size(); // Number of STAs

                     if (num_clients == 0){
                        System.out.println("[DemoStatistics] No clients associated");
                        break;
                     }
                     int[] clientsChannels = new int[num_clients];
                     // Various indexes
                     int client_index = 0;
                     int client_channel = 0;
                     ind_aux = 0;
                     for (OdinClient oc: clients) { // Create array with client channels and their indexes for better data processing

                       ind_aux = 0;

                       client_channel = getChannelFromAgent(oc.getLvap().getAgent().getIpAddress());

                       for (int chann: channels){

                         if (chann == client_channel){

                           clientsChannels[client_index] = ind_aux;
                           client_index++;
                           break;

                         }
                         ind_aux++;
                       }
                     }
                     for (channel = 0 ; channel < num_channels ; ++channel) {

                        if(channels[channel]==0)
                            continue;

                        int agent = 0;
                        scanningAgents.clear();
                        for (InetAddress agentAddr: agents) {

                            // Request statistics
                            result = requestScannedStationsStatsFromAgent(agentAddr, channels[channel], SCANNED_SSID);    
                            scanningAgents.put(agentAddr, result);
                        }         

                        try {
                            Thread.sleep(1000);
                        } 
                        catch (InterruptedException e) {
                            e.printStackTrace();
                        }

                        for (InetAddress agentAddr: agents) {

                            // Reception statistics 
                            if (scanningAgents.get(agentAddr) == 0) {
                              continue;       
                            }
                            vals_rx_value[channel][agent] = getScannedStaRssiFromAgent(agentAddr);
                            agent++;
                        }
                        //Thread.sleep(200); // Give some time to the AP
                     }
                     client_index = 0;
                    ind_aux = 0;

                    // For each client associated

                    for (OdinClient oc: clients) {

                    MACAddress eth = oc.getMacAddress(); // client MAC

                    client_channel = clientsChannels[client_index]; // row in the matrix

                    for ( ind_aux = 0; ind_aux < num_agents; ind_aux++){// For 

                        String arr = vals_rx_value[client_channel][ind_aux]; // String with "MAC rssi\nMAC rssi\n..."

                        Double rssi = getRssiFromRxStats(eth,arr); // rssi or -99.9

                        Double[] client_average_dBm = new Double[num_agents];

                        client_average_dBm = rssiData.get(eth);

                        if (client_average_dBm == null){// First time STA is associated

                        client_average_dBm = new Double[num_agents];
                        Arrays.fill(client_average_dBm,-99.9);
                        client_average_dBm[ind_aux] = rssi;

                        }else{

                        if((client_average_dBm[ind_aux]!=-99.9)&&(client_average_dBm[ind_aux]!=null)){
                            if(rssi!=-99.9){

                            Double client_signal = Math.pow(10.0, (rssi) / 10.0); // Linear power
                            Double client_average = Math.pow(10.0, (client_average_dBm[ind_aux]) / 10.0); // Linear power average
                            client_average = client_average*0.2 + client_signal*0.8;
                            client_average_dBm[ind_aux] = Double.valueOf((double)Math.round(1000*Math.log10(client_average))/100); //Average power in dBm with 2 decimals

                            }
                        }else{
                            client_average_dBm[ind_aux] = rssi;
                        }
                        }
                        rssiData.put(eth,client_average_dBm);
                    }
                    client_index++;
                    }
                    System.out.println("[DemoStatistics] =============================================================");
                    System.out.println(showAPsLine + " - RSSI [dBm]\033[00m");
                    for (OdinClient oc: clients) {

                        client_index = 0;

                        MACAddress eth = oc.getMacAddress(); // client MAC

                        Double[] client_dBm = new Double[num_agents];

                        InetAddress clientAddr = oc.getIpAddress();
                        InetAddress agentAddr = oc.getLvap().getAgent().getIpAddress();

                        if(clientAddr.equals(nullAddr))// If client not assigned, next one
                            continue;

                        System.out.println("[DemoStatistics] \t\t\t\tClient " + clientAddr + " in agent " + agentAddr);

                        client_dBm = rssiData.get(eth);

                        if (client_dBm != null){// Array with rssi

                            Double maxRssi = client_dBm[0]; // Start with first rssi

                            Double currentRssi = null;

                            for(ind_aux = 1; ind_aux < client_dBm.length; ind_aux++){//Get max position, VIP AP not considered

                                if(client_dBm[ind_aux]>maxRssi){
                                    maxRssi=client_dBm[ind_aux];
                                    client_index = ind_aux;
                                }
                            }

                            // Printf with colours
                            System.out.print("[DemoStatistics] ");



                            for(ind_aux = 0; ind_aux < client_dBm.length; ind_aux++){

                            if(agents[ind_aux].equals(agentAddr)){ // Current AP

                                currentRssi = client_dBm[ind_aux];

                                System.out.print("[\033[48;5;29;1m" + String.format("%.2f",client_dBm[ind_aux]) + "\033[00m]"); // Dark Green

                            }else{
                                if(ind_aux==client_index){

                                    System.out.print("[\033[48;5;88m" + String.format("%.2f",client_dBm[ind_aux]) + "\033[00m]"); // Dark red

                                }else{

                                    System.out.print("["+ String.format("%.2f",client_dBm[ind_aux]) +"]"); //
                                }
                            } 
                            }
                            System.out.println("");
                            // End prinft with colours  
                        }else{
                            System.out.println("[DemoStatistics] No data received");
                        }
                    }
                    rssiData.clear();
                     System.out.println("[DemoStatistics] =============================================================");
                     break;
            default: System.out.println("[DemoStatistics] Invalid option");
                     break;
        }
        promptEnterKey();
        System.out.print("\033[2J"); // Clear screen and cursor to 0,0
        
	    } catch (InterruptedException e) {
	      e.printStackTrace();
	    }
    }
  }
  
  
  static class MyHandler implements HttpHandler {
    @Override
    public void handle(HttpExchange t) throws IOException {
      String response = "This is the response";
      t.sendResponseHeaders(200, response.length());
      OutputStream os = t.getResponseBody();
      System.out.println("[DemoStatistics] HTTP REQUEST");
    }
  }

  public int promptKey(){ // Function to ask for a key
    int key;
    Scanner scanner = new Scanner(System.in);
    key = scanner.nextInt();
    return key;
  }
  public void promptEnterKey(){ // Function to ask for "ENTER"
   System.out.print("Press \"ENTER\" to continue...");
   Scanner scanner = new Scanner(System.in);
   scanner.nextLine();
  }
  private Double getRssiFromRxStats(MACAddress clientMAC, String arr){ // Process the string with all the data, it saves 2 ms if done inside the app vs. in agent

    for (String elem : arr.split("\n")){//Split string in STAs

      String row[] = elem.split(" ");//Split string in MAC and rssi

      if (row.length != 2) { // If there is more than 2 items, next one
        continue;
      }

      MACAddress eth = MACAddress.valueOf(row[0].toLowerCase());

      if (clientMAC.equals(eth)){//If it belongs to the client, return rssi

        Double rssi = Double.parseDouble(row[1]);

        if(rssi!=null)
          return rssi;
      }
    }
    return -99.9;//Not heard by the AP, return -99.9
  }
}
