package net.floodlightcontroller.odin.applications;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Arrays;
import java.util.ArrayList;
import java.io.File;
import java.io.PrintStream;
import java.math.*;

import net.floodlightcontroller.odin.master.OdinApplication;
import net.floodlightcontroller.odin.master.OdinClient;
import net.floodlightcontroller.odin.master.OdinEventFlowDetection;
import net.floodlightcontroller.odin.master.FlowDetectionCallback;
import net.floodlightcontroller.odin.master.FlowDetectionCallbackContext;
import net.floodlightcontroller.odin.master.OdinMaster.SmartApSelectionParams;
import net.floodlightcontroller.odin.master.OdinMaster.SmartApSelectionTextParams;
import net.floodlightcontroller.util.MACAddress;

public class SmartApSelectionText extends OdinApplication {

  // IMPORTANT: this application only works if all the agents in the
  //poolfile are activated before the end of the INITIAL_INTERVAL.
  // Otherwise, the application looks for an object that does not exist
  //and gets stopped

  private final int debugLevel = 1;
  
  // SSID to scan
  private final String SCANNED_SSID = "*";

  //Params
  private SmartApSelectionTextParams SMARTAP_TEXT_PARAMS;

  // Scanning agents
  Map<InetAddress, Integer> scanningAgents = new HashMap<InetAddress, Integer> ();
  int result; // Result for scanning

  HashSet<OdinClient> clients;
  Set<InetAddress> agents;

  private int[] channels = null;
  private int num_channels = 0;
  private int num_agents = 0;
  private String[][] vals_rx = null;


  private long time = 0L; // Compare timestamps in ms
  
  InetAddress nullAddr = null;
  InetAddress vipAPAddr = null;
  InetAddress nonVipAPAddr = null; // If the STA connects to VIP first, we need to handoff to other AP
  
  private int vip_index = 0;
  /**
  * Flow detection
  */
  private final String IPSrcAddress;				// Handle a IPSrcAddress or all IPSrcAddress ("*")
  private final String IPDstAddress;				// Handle a IPDstAddress or all IPDstAddress ("*")
  private final int protocol;						// Handle a protocol or all protocol ("*")
  private final int SrcPort;						// Handle a SrcPort or all SrcPort ("*")
  private final int DstPort;						// Handle a DstPort or all DstPort ("*")
  
  Map<InetAddress, DetectedFlow> flowsReceived = new HashMap<InetAddress, DetectedFlow> ();

  public SmartApSelectionText () {
    this.IPSrcAddress = "*";
    this.IPDstAddress = "*";
    this.protocol = 0;
    this.SrcPort = 0;
    this.DstPort = 0;
  }

  /**
  * Register flow detection
  */
  private void initDetection () {
		OdinEventFlowDetection oefd = new OdinEventFlowDetection();
		oefd.setFlowDetection(this.IPSrcAddress, this.IPSrcAddress, this.protocol, this.SrcPort, this.DstPort); 
		FlowDetectionCallback cb = new FlowDetectionCallback() {
			@Override
			public void exec(OdinEventFlowDetection oefd, FlowDetectionCallbackContext cntx) {
					handler(oefd, cntx);
			}
		};
		/* Before executing this line, make sure the agents declared in poolfile are started */	
		registerFlowDetection(oefd, cb);
  }
  /**
   * Condition for a handoff
   *
   * Example of params in poolfile imported in SMARTAP_TEXT_PARAMS:
   *
   * SMARTAP_TEXT_PARAMS.HYSTERESIS_THRESHOLD = 4;
   * SMARTAP_TEXT_PARAMS.SIGNAL_THRESHOLD = -56;
   *
   * With these parameters a hand off will start when:
   *
   * The Rssi received from a specific client is below -56 dBm, there is another AP with better received Rssi and a previous hand off has not happened in the last 4000 ms
   *
   */

  @Override
  public void run() {
    if (debugLevel >= 1) {
      System.out.println("[SmartApSelectionText] Starting");
    }
    this.SMARTAP_TEXT_PARAMS = getSmartApSelectionTextParams();
    
    // first half of the initial sleep
    try {
      if (debugLevel >= 1) {
        System.out.println("[SmartApSelectionText] You have " + SMARTAP_TEXT_PARAMS.time_to_start/1000 + " s to start the agents");
      }
      Thread.sleep(SMARTAP_TEXT_PARAMS.time_to_start/2);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    
    // second half of the sleep
    try {
      if (debugLevel >= 1) {
        System.out.println("[SmartApSelectionText] You have " + SMARTAP_TEXT_PARAMS.time_to_start/2000 + " s to start the agents");
      }
      Thread.sleep(SMARTAP_TEXT_PARAMS.time_to_start/2);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
    
    // Write on file integration
    PrintStream ps = null;
    
    if(SMARTAP_TEXT_PARAMS.filename.length() > 0) {
      File f = new File(SMARTAP_TEXT_PARAMS.filename);
      if (debugLevel > 0) {
        System.out.println("[SmartApSelectionText] Log file name: " + SMARTAP_TEXT_PARAMS.filename);
      }            
      try {
        ps = new PrintStream(f);
      } catch (Exception e) {
        e.printStackTrace();
      }
    }
    
    // Get the number of agents that have been included in poolfile
    agents = getAgents();
    num_agents = agents.size(); // Number of agents
    if (debugLevel >= 1) {
      System.out.println("[SmartApSelectionText] " + num_agents + " agents included in poolfile");
      // print the IP addresses of the agents
      for (InetAddress agentAddr: agents) {
        System.out.println("[SmartApSelectionText] Agent: " + agentAddr);
      }     
    }
    
    // check if every agent is alive
    if (debugLevel >= 1) {
      System.out.println("[SmartApSelectionText] Checking if all the agents included in poolfile are alive. If they are not, the application will stop");
    }
    for (InetAddress agentAddr: agents) {
      if (debugLevel >= 1) {
        System.out.println("[SmartApSelectionText] Checking agent: " + agentAddr);
        System.out.print("[SmartApSelectionText] Last ping heard: ");
      }
      long lastMomentHeard = getLastHeardFromAgent(agentAddr);
      if (debugLevel >= 1) {
        System.out.println(lastMomentHeard);
      }
    }    
    
    // Array to store the channels in use
    channels = new int[num_agents];
    int[] channelsAux = new int[num_agents];

    // print the parameters to the log file
    ps.println("[SmartApSelectionText] Log file " + SMARTAP_TEXT_PARAMS.filename);
    ps.println("[SmartApSelectionText] Parameters:");
    ps.println("\tTime_to_start: " + SMARTAP_TEXT_PARAMS.time_to_start);
    ps.println("\tScanning_interval: " + SMARTAP_TEXT_PARAMS.scanning_interval);
    ps.println("\tAdded_time: " + SMARTAP_TEXT_PARAMS.added_time);
    ps.println("\tSignal_threshold: " + SMARTAP_TEXT_PARAMS.signal_threshold);
    ps.println("\tHysteresis_threshold: " + SMARTAP_TEXT_PARAMS.hysteresis_threshold);
    ps.println("\tPrevius_data_weight (alpha): " + SMARTAP_TEXT_PARAMS.weight);
    ps.println("\tPause between scans: " + SMARTAP_TEXT_PARAMS.pause);
    ps.println("\tMode: " + SMARTAP_TEXT_PARAMS.mode);
    ps.println("\tTxpowerSTA: " + SMARTAP_TEXT_PARAMS.txpowerSTA);
    ps.println("\tTxpowerSTA: " + SMARTAP_TEXT_PARAMS.thReqSTA);
    ps.println("\tFilename: " + SMARTAP_TEXT_PARAMS.filename);

    // print the parameters
    if (debugLevel >= 1) {
      System.out.println("[SmartApSelectionText] Log file " + SMARTAP_TEXT_PARAMS.filename);
      System.out.println("[SmartApSelectionText] Parameters:");
      System.out.println("\tTime_to_start: " + SMARTAP_TEXT_PARAMS.time_to_start);
      System.out.println("\tScanning_interval: " + SMARTAP_TEXT_PARAMS.scanning_interval);
      System.out.println("\tAdded_time: " + SMARTAP_TEXT_PARAMS.added_time);
      System.out.println("\tSignal_threshold: " + SMARTAP_TEXT_PARAMS.signal_threshold);
      System.out.println("\tHysteresis_threshold: " + SMARTAP_TEXT_PARAMS.hysteresis_threshold);
      System.out.println("\tPrevius_data_weight (alpha): " + SMARTAP_TEXT_PARAMS.weight);
      System.out.println("\tPause between scans: " + SMARTAP_TEXT_PARAMS.pause);
      System.out.println("\tMode: " + SMARTAP_TEXT_PARAMS.mode);
      System.out.println("\tTxpowerSTA: " + SMARTAP_TEXT_PARAMS.txpowerSTA);
      System.out.println("\tTxpowerSTA: " + SMARTAP_TEXT_PARAMS.thReqSTA);
      System.out.println("\tFilename: " + SMARTAP_TEXT_PARAMS.filename);
    }
    
    String showAPsLine = "\033[K\r[SmartApSelectionText] ";
    
    try { // Create IP addresses for null and for VIP AP to compare with clients not assigned
      nullAddr = InetAddress.getByName("0.0.0.0");
      vipAPAddr = InetAddress.getByName(getVipAPIpAddress());
    } catch (UnknownHostException e) {
      e.printStackTrace();
    }
    
    int ind_aux = 0;

    if (debugLevel >= 1) {
      System.out.println("[SmartApSelectionText] Getting channels from the agents");
    }

    // Get channels from the agents, assuming there is no change in all operation, if already in array->0
    for (InetAddress agentAddr: agents) {

      String hostIP = agentAddr.getHostAddress(); // Build line for user interface
      showAPsLine = showAPsLine + "\033[0;1m[ AP" + hostIP.substring(hostIP.lastIndexOf('.')+1,hostIP.length()) + " ]";
      if (debugLevel >= 1) {
        System.out.println("[SmartApSelectionText] Trying to get the channel from agent " + agentAddr);
      }
      
      // try to get the channel
      // it may fail if the agent is not alive
      int chann;
      chann = getChannelFromAgent(agentAddr);

      if (debugLevel >= 1) {
        System.out.println("[SmartApSelectionText] AP " + agentAddr + " is in channel " + chann);
      }
      ps.println("[SmartApSelectionText] AP " + agentAddr + " is in channel: " + chann); // Log in file
      
      // add this channel to the array of channels to be used
      Arrays.sort(channelsAux);
      //System.out.println("[SmartApSelectionText] Search for "+ chann + ": " + Arrays.binarySearch(channelsAux, chann));

      if(Arrays.binarySearch(channelsAux, chann) < 0){// if already in array, not necessary to add it
        channelsAux[num_channels] = chann;
        channels[num_channels] = chann;
        if (debugLevel >= 1) {
          System.out.println("[SmartApSelectionText] Channel " + chann + " added to the array " + Arrays.toString(channels));
        }
      }
      
      if (debugLevel >= 1) {
        System.out.println("[SmartApSelectionText] Channels used by the agents: " + Arrays.toString(channels));
      }

      // check if I have found the VIP agent
      if(agentAddr.equals(vipAPAddr)){
        vip_index=ind_aux;
      }else{
        nonVipAPAddr = agentAddr;
      }
      num_channels++;
      ind_aux++;
    }

    ps.println("[SmartApSelectionText]");
    ps.flush();

    // I have all the required data. I can now start the application
    // show a countdown on the screen, just to let the user see the result
    for (int countdown = 5; countdown > 0; countdown --) {
      try {
        if (debugLevel > 0) {
          System.out.println("[SmartApSelectionText] Channel info gathered. Starting smartAPSelectionText in " + countdown + " s");
        }
        Thread.sleep(1000);
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
    
    // start the application
    vals_rx = new String[num_channels][num_agents]; // Matrix to store the results from agents
    // Map to store RSSI for each STA in all APs
    Map<MACAddress, Double[]> rssiData = new HashMap<MACAddress, Double[]> (); 

    // Map to store last handoff for each STA FIXME: Maybe create struct
    Map<MACAddress, Long> handoffDate = new HashMap<MACAddress, Long> (); 

    // Map to store Throughput available for each STA in all APs
    Map<MACAddress, Double[]> ffData = new HashMap<MACAddress, Double[]> ();

    System.out.print("\033[2J"); // Clear screen and cursor to 0,0
    char[] progressChar = new char[] { '-', '\\', '|', '/' };
    int progressIndex = 0;

    initDetection (); // Register flow detection

    while (true) {
      try {
        Thread.sleep(100);

        // restart the clients hashset in order to see if there are new STA
        clients = new HashSet<OdinClient>(getClients());

        int num_clients = clients.size(); // Number of STAs

        if (num_clients == 0){ // No clients, no need of scan
          System.out.println("\033[K\r[SmartApSelectionText] ====================");
          System.out.println("\033[K\r[SmartApSelectionText] Proactive AP Handoff");
          System.out.println("\033[K\r[SmartApSelectionText]");
          System.out.println("\033[K\r[SmartApSelectionText] " + progressChar[progressIndex++] + "No clients associated, waiting for connection");
          System.out.println("\033[K\r[SmartApSelectionText] ====================");
          if(progressIndex==3)
            progressIndex=0;
          System.out.print("\033[K\r\n\033[K\r\n\033[K\r\n\033[K\r\n\033[K\r\n\033[K\r\n\033[K\r\n\033[K\r\n\033[K\r\n\033[0;0H"); // Clear lines above and return to console 0,0
          continue;
        }

        // if there are clients
        int[] clientsChannels = new int[num_clients]; // Array with the indexes of channels, better performance in data process


        // Various indexes
        int client_index = 0;
        int client_channel = 0;
        ind_aux = 0;

        System.out.println("\033[K\r[SmartApSelectionText] ====================");
        System.out.println("\033[K\r[SmartApSelectionText] Proactive AP Handoff");
        System.out.println("\033[K\r[SmartApSelectionText]");

        for (OdinClient oc: clients) { // Create array with client channels and their indexes for better data processing

          ind_aux = 0;
          // get the channel of this client
          // this requires the use of the 'odinagent.channel' handler
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

        time = System.currentTimeMillis();

        //For each channel used in owned APs
        for (int channel = 0 ; channel < num_channels ; ++channel) {

          if(channels[channel]==0)
            continue;

          int agent = 0;
          scanningAgents.clear();
          for (InetAddress agentAddr: agents) {
            System.out.println("\033[K\r[SmartApSelectionText] Requesting statistics from an agent " + agentAddr);

            // Request statistics
            result = requestScannedStationsStatsFromAgent(agentAddr, channels[channel], SCANNED_SSID);// this uses the write handler WRITE_HANDLER_SCAN_APS
            scanningAgents.put(agentAddr, result);

            System.out.println("\033[K\r[SmartApSelectionText] Requested statistics from an agent " + agentAddr);
          }         

          // wait until the end of the scanning interval
          try {
            Thread.sleep(SMARTAP_TEXT_PARAMS.scanning_interval + SMARTAP_TEXT_PARAMS.added_time);
          } 
          catch (InterruptedException e) {
            e.printStackTrace();
          }

          // retrieve the statistics scanned by each agent
          for (InetAddress agentAddr: agents) {
            System.out.println("\033[K\r[SmartApSelectionText] Retrieving statistics from an agent " + agentAddr);

            // Reception statistics 
            if (scanningAgents.get(agentAddr) == 0) {
              System.out.println("\033[K\r[SmartApSelectionText] Agent BUSY during scanning operation");
              continue;       
            }

            System.out.println("\033[K\r[SmartApSelectionText] Retrieved statistics from an agent (1) " + agentAddr);

            vals_rx[channel][agent] = getScannedStaRssiFromAgent(agentAddr);

            System.out.println("\033[K\r[SmartApSelectionText] Retrieved statistics from an agent (2) " + agentAddr);

            agent++;
          }
          //Thread.sleep(200); // Give some time to the AP
        }
        ps.println("[SCAN] " + (System.currentTimeMillis()-time)); // Log in file
        System.out.println("\033[K\r[SmartApSelectionText] Scanning done in: " + (System.currentTimeMillis()-time) + " ms");

        // All the statistics stored, now process
        time = System.currentTimeMillis();
        client_index = 0;
        ind_aux = 0;

        // For each STA (client) associated, store the RSSI value with which the APs "see" it
        for (OdinClient oc: clients) {

          MACAddress eth = oc.getMacAddress(); // client MAC

          client_channel = clientsChannels[client_index]; // row in the matrix

          for ( ind_aux = 0; ind_aux < num_agents; ind_aux++){ 

            String arr = vals_rx[client_channel][ind_aux]; // String with "MAC rssi\nMAC rssi\n..."

            Double rssi = getRssiFromRxStats(eth,arr); // rssi or -99.9

            Double[] client_average_dBm = new Double[num_agents];

            // get the stored RSSI averaged value (historical data)
            client_average_dBm = rssiData.get(eth);

            if (client_average_dBm == null){// First time STA is associated

              client_average_dBm = new Double[num_agents];
              // first, we put -99.9 everywhere
              Arrays.fill(client_average_dBm,-99.9);
              // put the last value instead of -99.9
              client_average_dBm[ind_aux] = rssi;

            }else{

              // Recalculate the new average
              if((client_average_dBm[ind_aux]!=-99.9)&&(client_average_dBm[ind_aux]!=null)){
                if(rssi!=-99.9){
                  // Linear power
                  Double client_signal = Math.pow(10.0, (rssi) / 10.0); 
                  // Linear power average
                  Double client_average = Math.pow(10.0, (client_average_dBm[ind_aux]) / 10.0); 
                  // use the "alpha" parameter (weight) to calculate the new value
                  client_average = client_average*(1-SMARTAP_TEXT_PARAMS.weight) + client_signal*SMARTAP_TEXT_PARAMS.weight;
                  //Average power in dBm with 2 decimal positions
                  client_average_dBm[ind_aux] = Double.valueOf((double)Math.round(1000*Math.log10(client_average))/100); 
                }
              }else{
                // It is the first time we have data of this STA in this AP
                client_average_dBm[ind_aux] = rssi;
              }
            }
            // Store all the data
            rssiData.put(eth,client_average_dBm);
          }
          client_index++;
        }
        ps.println("[PROCESS] " + (System.currentTimeMillis()-time)); // Log in file
        System.out.println("\033[K\r[SmartApSelectionText] Processing done in: " + (System.currentTimeMillis()-time) + " ms");
        System.out.println("\033[K\r[SmartApSelectionText] ====================");
        System.out.println("\033[K\r[SmartApSelectionText] ");

        System.out.println(showAPsLine + " - RSSI [dBm]\033[00m");

        // Now perform comparation and handoff if  needed
        time = System.currentTimeMillis();

        ps.println(time + " ms"); // Log in file

        // Array with the IP addresses of the Agents
        InetAddress[] agentsArray = agents.toArray(new InetAddress[0]);

        // Write to screen the updated value of the averaged RSSI
        for (OdinClient oc: clients) {

          client_index = 0;

          MACAddress eth = oc.getMacAddress(); // client MAC

          Double[] client_dBm = new Double[num_agents];

          InetAddress clientAddr = oc.getIpAddress();
          InetAddress agentAddr = oc.getLvap().getAgent().getIpAddress();

          // If client not assigned, go to next one (associated, but without IP address)
          if(clientAddr.equals(nullAddr))
            continue;

          System.out.println("\033[K\r[SmartApSelectionText] \t\t\t\tClient " + clientAddr + " in agent " + agentAddr);
          ps.println("\tClient " + clientAddr + " in agent " + agentAddr); // Log in file

          client_dBm = rssiData.get(eth);

          if (client_dBm != null){// Array with rssi

            Double maxRssi = client_dBm[0]; // Start with first rssi

            Double currentRssi = null;
            //Get the index of the AP where the STA has the highest RSSI, VIP AP not considered
            for(ind_aux = 1; ind_aux < client_dBm.length; ind_aux++){

              if((client_dBm[ind_aux]>maxRssi)&&(!vipAPAddr.equals(agentsArray[ind_aux]))){
                maxRssi=client_dBm[ind_aux];
                client_index = ind_aux;
              }
            }

            // Printf with colours
            System.out.print("\033[K\r[SmartApSelectionText] ");

            // write to the screen the information with colours
            for(ind_aux = 0; ind_aux < client_dBm.length; ind_aux++){

              if(agentsArray[ind_aux].equals(agentAddr)){ // Current AP

                currentRssi = client_dBm[ind_aux];
                if(agentsArray[ind_aux].equals(vipAPAddr)){
                  System.out.print("[\033[48;5;3;1m" + String.format("%.2f",client_dBm[ind_aux]) + "\033[00m]"); // Olive
                }else{
                  System.out.print("[\033[48;5;29;1m" + String.format("%.2f",client_dBm[ind_aux]) + "\033[00m]"); // Dark Green
                }
                ps.println("\t\t[Associated] Rssi in agent " + agentsArray[ind_aux] + ": " + client_dBm[ind_aux] + " dBm"); // Log in file

              }else{
                if(ind_aux==client_index){ // Max, VIP AP not considered

                  System.out.print("[\033[48;5;88m" + String.format("%.2f",client_dBm[ind_aux]) + "\033[00m]"); // Dark red
                  ps.println("\t\t[BetterAP] Rssi in agent " + agentsArray[ind_aux] + ": " + client_dBm[ind_aux] + " dBm"); // Log in file

                }else{
                  if(agentsArray[ind_aux].equals(vipAPAddr)){
                    System.out.print("[\033[48;5;94m" + String.format("%.2f",client_dBm[ind_aux]) + "\033[00m]"); // Orange
                  }else{
                    System.out.print("["+ String.format("%.2f",client_dBm[ind_aux]) +"]"); //
                  }
                  ps.println("\t\t[WorseAP] Rssi in agent " + agentsArray[ind_aux] + ": " + client_dBm[ind_aux] + " dBm"); // Log in file
                }
              } 
            }
            // End prinft with colours

            // If you also want a threshold in FF mode, substitute the next line with if(!SMARTAP_TEXT_PARAMS.mode.equals("FF"))
            if(true) { // In BALANCER mode, it will assign STAs to APs always with higher RSSI than threshold, so there is no ping pong effect 

              // Change to the best RSSI
              if (!agentsArray[client_index].equals(agentAddr)){ 

                //If RSSI threshold is reached, handoff
                if(currentRssi<SMARTAP_TEXT_PARAMS.signal_threshold){

                  Long handoffTime = handoffDate.get(eth);

                  //If Time threshold is reached, handoff
                  if((handoffTime==null)||((System.currentTimeMillis()-handoffTime.longValue())/1000>SMARTAP_TEXT_PARAMS.hysteresis_threshold)){

                    handoffClientToAp(eth,agentsArray[client_index]);
                    // store the time for checking the hysteresis next time
                    handoffDate.put(eth,Long.valueOf(System.currentTimeMillis()));
                    System.out.println(" - Handoff >--->--->---> "+agentsArray[client_index]);
                    ps.println("\t\t[Action] Handoff to agent: " + agentsArray[client_index]); // Log in file

                  }else{
                    System.out.println(" - No Handoff: Hysteresis time not reached");
                    ps.println("\t\t[No Action] No Handoff: Hysteresis time not reached"); // Log in file
                  }
                }else{
                  // The threshold is not reached
                  if(SMARTAP_TEXT_PARAMS.mode.equals("RSSI")){
                    System.out.println(" - No Handoff: Rssi Threshold not reached");
                    ps.println("\t\t[No Action] No Handoff: Rssi Threshold not reached"); // Log in file
                  }else if(SMARTAP_TEXT_PARAMS.mode.equals("DETECTOR")){
                    System.out.println(" - Assigned by DETECTOR");
                    ps.println("\t\t[No Action] No Handoff: Assigned by DETECTOR"); // Log in file
                  }else if(SMARTAP_TEXT_PARAMS.mode.equals("FF")){
                    System.out.println(" - Assigned by FF");
                    ps.println("\t\t[No Action] No Handoff: Assigned by FF"); // Log in file
                  }else{
                    System.out.println(" - Assigned by BALANCER");
                    ps.println("\t\t[No Action] No Handoff: Assigned by BALANCER"); // Log in file
                  }
                }
              }else{
                System.out.println(""); // Best AP already
                ps.println("\t\t[No Action] There is no better Rssi heard"); // Log in file
              }
            }

            // FF mode
            if(SMARTAP_TEXT_PARAMS.mode.equals("FF")){
              // Calculate FF data
              System.out.println("");

              ind_aux = 0;
              Double[] TH_av = new Double[num_agents];

              for (InetAddress agentAddrFF: agents) {

                // If the STA is associated to this agent, use the real statistics
                if(oc.getLvap().getAgent().getIpAddress().equals(agentAddrFF)){
                  // Reception statistics
                  Map<MACAddress, Map<String, String>> vals_rx_FF = getRxStatsFromAgent(agentAddrFF);
                  // Look for the statistics corresponding to this client (using the eth address)
                  Map<String, String> vals_entry_rx = vals_rx_FF.get(eth);
                  if(vals_entry_rx != null){
                    //System.out.println("\033[K\r[SmartApSelectionText] avg rate: " + vals_entry_rx.get("avg_rate") + " kbps");
                    Double clientRate = Double.parseDouble(vals_entry_rx.get("avg_rate"));
                    // t and T
                    double[] tTValues = getTransmissionTime(clientRate.doubleValue());
                    double p = 0.98*(tTValues[1]/tTValues[0]);
                    //System.out.println("\033[K\r[SmartApSelectionText] Th_av["+ind_aux+"]: " + String.format("%.2f",clientRate.doubleValue()*p));
                    TH_av[ind_aux] = clientRate.doubleValue()*p;
                  }else{
                    TH_av[ind_aux] = 0.0;
                  }

                }else{
                  // if the STA is NOT associated to this agent, estimate the available throughput
                  double txpowerAP = Math.pow(10.0, (getTxPowerFromAgent(agentAddrFF)) / 10.0);
                  double txpowerSTA = Math.pow(10.0, (SMARTAP_TEXT_PARAMS.txpowerSTA) / 10.0);
                  double rssiDL = client_dBm[ind_aux]+10.0*Math.log10(txpowerAP/txpowerSTA);
                  double snr = 90.0 + rssiDL;
                  double maxRate = getOFDMRates(snr);
                  double[] tTValues = getTransmissionTime(maxRate);

                  HashSet<OdinClient> clients_FF = new HashSet<OdinClient>(getClientsFromAgent(agentAddrFF));
                  double t2Value = calculateT2(clients_FF.size(),tTValues[0]);
                  double p = 0.98*(tTValues[1]/t2Value);
                  //System.out.println("\033[K\r[SmartApSelectionText] Th_av["+ind_aux+"]: " + String.format("%.2f",maxRate*p));
                  TH_av[ind_aux] = maxRate*p;
                }
                ind_aux++;
              }
              // Save TH_av in map
              ffData.put(eth,TH_av);
            }
          }else{
            System.out.println("\033[K\r[SmartApSelectionText] No data received");
          }
        }

        if(SMARTAP_TEXT_PARAMS.mode.equals("FF")){ // Show FF results and handoff if necessary
          System.out.println("\033[K\r[SmartApSelectionText] ====================");
          System.out.println(showAPsLine + " - FF Throughput available [Mbps]\033[00m");

          // obtain the FF values for each client on each AP
          for (OdinClient oc: clients) {

            ind_aux = 0;
            client_index = 0;
            MACAddress eth = oc.getMacAddress(); // client MAC
            InetAddress clientAddr = oc.getIpAddress();
            InetAddress agentAddr = oc.getLvap().getAgent().getIpAddress();

            if(clientAddr.equals(nullAddr))// If client not assigned, next one
              continue;

            System.out.println("\033[K\r[SmartApSelectionText] \t\t\t\tClient " + clientAddr + " in agent " + agentAddr);
            ps.println("\tClient " + clientAddr + " in agent " + agentAddr); // Log in file

            Double[] th_avFF = ffData.get(eth);
            //System.out.println("\033[K\r[SmartApSelectionText] th_avFF= "+Arrays.toString(th_avFF));
            Double maxFF = calculateFittingnessFactor(SMARTAP_TEXT_PARAMS.thReqSTA,th_avFF[0]); // Start with first Th_av
            Double currentTh_av = null;

            System.out.print("\033[K\r[SmartApSelectionText] ff["+ind_aux+"]=" + String.format("%.3f",maxFF) + " ");
            
            ArrayList<Integer> th_list = new ArrayList<Integer>(); // To sort FF
            th_list.add(0); // First FF

            for(ind_aux = 1; ind_aux < th_avFF.length; ind_aux++){//Get max position and calculate FF

              Double currentFF = calculateFittingnessFactor(SMARTAP_TEXT_PARAMS.thReqSTA,th_avFF[ind_aux]);
              boolean added_FF = false;

              for(int ind_list = 0; ind_list < th_list.size(); ind_list++){
        
                if(currentFF>th_list.get(ind_list)){
                  maxFF=currentFF;
                  client_index = ind_aux;
                  th_list.add(ind_list,ind_aux);
                  added_FF = true;
                  break;
                }
              }
              if(!added_FF)
                th_list.add(ind_aux); // Not max FF
              
              System.out.print("ff["+ind_aux+"]=" + String.format("%.3f",currentFF) + " ");
            }
            System.out.println("");
            System.out.print("\033[K\r[SmartApSelectionText] ");

            // Print the results with colours
            for(ind_aux = 0; ind_aux < th_avFF.length; ind_aux++){

              if(agentsArray[ind_aux].equals(agentAddr)){ // Current AP 

                currentTh_av = th_avFF[ind_aux];
                if(currentTh_av!=0.0){
                  System.out.print("[\033[48;5;29;1m" + String.format("%.2f",th_avFF[ind_aux]/1000.0) + "\033[00m]"); // Dark Green
                  ps.println("\t\t[Associated] Throughput in agent " + agentsArray[ind_aux] + ": " + th_avFF[ind_aux] + " kbps"); // Log in file
                }else{
                  System.out.print("[\033[48;5;29;1m" + "-----" + "\033[00m]"); // Dark Green
                  ps.println("\t\t[Associated] No packets received"); // Log in file
                }
              }else{
                if(ind_aux==client_index){ // Max

                  System.out.print("[ \033[48;5;88m" + String.format("%.2f",th_avFF[ind_aux]/1000.0) + "\033[00m]"); // Dark red
                  ps.println("\t\t[BetterAP] Throughput in agent " + agentsArray[ind_aux] + ": " + th_avFF[ind_aux] + " kbps"); // Log in file

                }else{
                  System.out.print("[ "+ String.format("%.2f",th_avFF[ind_aux]/1000.0) +"]"); //
                  ps.println("\t\t[WorseAP] Throughput in agent " + agentsArray[ind_aux] + ": " + th_avFF[ind_aux] + " kbps"); // Log in file
                }
              } 
            }

            for(int ind_list = 0; ind_list < th_list.size(); ind_list++){
            
              client_index = th_list.get(ind_list);
            
              // Order the handoff to the AP with the highest FF
              if (!agentsArray[client_index].equals(agentAddr)){ // Change to the best FF

                //If Rssi threshold is reached, check hystheresis
                Double[] client_dBm = rssiData.get(eth);
                Double currentRssi = client_dBm[client_index];
                if(currentRssi<SMARTAP_TEXT_PARAMS.signal_threshold){
                
                  Long handoffTime = handoffDate.get(eth);

                  //If Time hysteresis has expired, handoff
                  if((handoffTime==null)||((System.currentTimeMillis()-handoffTime.longValue())/1000>SMARTAP_TEXT_PARAMS.hysteresis_threshold)){

                  // make sure that you have received at least one packet
                  if(!(currentTh_av==0.0)){
                    handoffClientToAp(eth,agentsArray[client_index]);
                    handoffDate.put(eth,Long.valueOf(System.currentTimeMillis()));
                    System.out.println("\033[0;1m - Handoff >--->--->---> "+agentsArray[client_index]+"\033[00m");
                    ps.println("\t\t[Action] Handoff to agent: " + agentsArray[client_index]); // Log in file
                    break;
                  }else{
                    System.out.println(""); // No packets received
                    ps.println("\t\t[No Action] No packets received"); // Log in file
                    break;
                  }
                  }else{
                  System.out.println("\033[0;1m - No Handoff: Hysteresis time not reached\033[00m");
                  ps.println("\t\t[No Action] No Handoff: Hysteresis time not reached"); // Log in file
                  break;
                  }
                }else{
                  //System.out.println(" - No Handoff: Rssi Threshold not reached");
                  ps.println("\t\t[No Action] No Handoff: Rssi Threshold not reached, try next FF"); // Log in file
                  continue;
                }
              }else{
                System.out.println(""); // Best AP already
                ps.println("\t\t[No Action] There is no better FF"); // Log in file
                break;
              }
            }
            /*
            if (!agentsArray[client_index].equals(agentAddr)){ // Change to the best FF

              Long handoffTime = handoffDate.get(eth);

              //If Time threshold is reached, handoff
              if((handoffTime==null)||((System.currentTimeMillis()-handoffTime.longValue())/1000>SMARTAP_TEXT_PARAMS.hysteresis_threshold)){

                if(!(currentTh_av==0.0)){
                  handoffClientToAp(eth,agentsArray[client_index]);
                  handoffDate.put(eth,Long.valueOf(System.currentTimeMillis()));
                  System.out.println("\033[0;1m - Handoff >--->--->---> "+agentsArray[client_index]+"\033[00m");
                  ps.println("\t\t[Action] Handoff to agent: " + agentsArray[client_index]); // Log in file
                }else{
                  System.out.println(""); // No rate received
                }  
              }else{
                System.out.println("\033[0;1m - No Handoff: Hysteresis time not reached\033[00m");
                ps.println("\t\t[No Action] No Handoff: Hysteresis time not reached"); // Log in file
              }

            }else{
              System.out.println(""); // Best AP already
              ps.println("\t\t[No Action] There is no better FF"); // Log in file
            }
            */
          }
          System.out.println("\033[K\r[SmartApSelectionText] ====================");
        }



        // BALANCER and JAIN-BALANCER modes
        if((SMARTAP_TEXT_PARAMS.mode.equals("BALANCER"))||(SMARTAP_TEXT_PARAMS.mode.equals("JAIN-BALANCER"))){

          Map<MACAddress, InetAddress> assignedClients = new HashMap<MACAddress, InetAddress> (); // Array with the balancer decission MAC of the STA - IP of the AP

          System.out.println("\033[K\r[SmartApSelectionText] ====================");
          if(SMARTAP_TEXT_PARAMS.mode.equals("JAIN-BALANCER")){
            
            System.out.println(showAPsLine + " - Jain's Fairness index Balancer\033[00m");
            System.out.print("\033[K\r[SmartApSelectionText] ");
            assignedClients = jainsFairnessIndex(rssiData, agentsArray, clients, SMARTAP_TEXT_PARAMS.signal_threshold); // More complex algorithm
          
          }else{
            
            System.out.println(showAPsLine + " - Balancer\033[00m");
            System.out.print("\033[K\r[SmartApSelectionText] ");
            assignedClients = simpleBalancerAlgorithm(rssiData, agentsArray, clients, SMARTAP_TEXT_PARAMS.signal_threshold); // Very simple balancer algorithm
            System.out.println("");  
          }
          
          // for each STA for which a handoff has been ordered
          for(MACAddress eth:assignedClients.keySet()){
          
            Long handoffTime = handoffDate.get(eth);
            System.out.print("\033[K\r[SmartApSelectionText] ");
            OdinClient clientHandoff = getClientFromHwAddress(eth);
            
            // Check hysteresis
            if((handoffTime==null)||((System.currentTimeMillis()-handoffTime.longValue())/1000>SMARTAP_TEXT_PARAMS.hysteresis_threshold)){
              
              InetAddress assignedAgent = assignedClients.get(eth);

              // Do the handoff
              if(getClientFromHwAddress(eth)!=null){
                handoffClientToAp(eth,assignedAgent);
                handoffDate.put(eth,Long.valueOf(System.currentTimeMillis()));
                System.out.print("\033[0;1mHandoff "+clientHandoff.getIpAddress()+" >--->--->---> "+assignedAgent+"\033[00m");
                ps.println("\t\t[Action] Handoff "+clientHandoff.getIpAddress()+" to agent: " + assignedAgent); // Log in file
              }
              
            }else{
            
              System.out.print("No Handoff "+clientHandoff.getIpAddress()+": Hysteresis time not expired");
              ps.println("\t\t[No Action] No Handoff: Hysteresis time not expired"); // Log in file
              
            }
            System.out.println("");
          }
        }


        if(SMARTAP_TEXT_PARAMS.mode.equals("DETECTOR")){ // If a flow is detected, the STA is moved to the VIP AP FIXME minimum rssi
          System.out.println("\033[K\r[SmartApSelectionText] ====================");
          System.out.println(showAPsLine + " - DETECTOR - AP VIP: "+vipAPAddr+"\033[00m");
          System.out.print("\033[K\r[SmartApSelectionText] ");
          printAgentsLoad(agentsArray,vipAPAddr); // Print load and VIP agent
          System.out.println("");
          for(OdinClient oc:clients){ // All clients
            MACAddress eth = oc.getMacAddress(); // client MAC
            InetAddress clientAddr = oc.getIpAddress(); // client IP
            
            if(flowsReceived.containsKey(clientAddr)){
              DetectedFlow cntx = flowsReceived.get(clientAddr);
              /*System.out.print("\033[K\r\t[Flow]     -> Source IP: " + cntx.IPSrcAddress + "\n");
              System.out.print("\033[K\r\t[Flow]     -> Destination IP: " + cntx.IPDstAddress + "\n");
              System.out.print("\033[K\r\t[Flow]     -> Protocol IP: " + cntx.protocol + "\n");
              System.out.print("\033[K\r\t[Flow]     -> Source Port: " + cntx.SrcPort + "\n");
              System.out.print("\033[K\r\t[Flow]     -> Destination Port: " + cntx.DstPort + "\n");
              System.out.print("\033[K\r\t[Flow] from agent: " + cntx.odinAgentAddr + " at " + cntx.timeStamp + "\n");*/
              
              if((System.currentTimeMillis()-cntx.timeStamp)>30000){ // Clean flow after 30 sec
                flowsReceived.remove(clientAddr);
                System.out.print("\033[K\r\t[Flow] Clean flow from client " + clientAddr + " - Handoff\n");
                handoffClientToAp(eth,cntx.lastAgentAddr);
              }else{
                InetAddress agentAddr = oc.getLvap().getAgent().getIpAddress();
                if(!vipAPAddr.equals(agentAddr)){
                  Double[] client_dBm = rssiData.get(eth);
                  if(client_dBm[vip_index]>SMARTAP_TEXT_PARAMS.signal_threshold){
                    System.out.print("\033[K\r\t[Flow] Detected flow from client " + clientAddr + " - Handoff\n");
                    cntx.lastAgentAddr = agentAddr;
                    flowsReceived.put(clientAddr,cntx);
                    handoffClientToAp(eth,vipAPAddr);
                  }else{
                    System.out.print("\033[K\r\t[Flow] Detected flow from client " + clientAddr + " - Signal threshold NOT reached\n");
                  }
                }else{
                  System.out.print("\033[K\r\t[Flow] " + clientAddr + " already in VIP AP\n");
                }
              }
            }/*else{
              System.out.print("\033[K\r\t[Flow] No flow for client "+clientAddr+"\n");
            }*/
          }

          // A new STA may have associated to the VIP AP. Remove it from there. This can be improved. FIXME
          for(OdinClient oc:getClientsFromAgent(vipAPAddr)){ // In case STA is associated before the app stars
            MACAddress eth = oc.getMacAddress(); // client MAC
            InetAddress clientAddr = oc.getIpAddress(); // client IP
            
            if(!flowsReceived.containsKey(clientAddr)){
              handoffClientToAp(eth,nonVipAPAddr);
            }
          }
        }
        ps.flush();
        System.out.println("\033[K\r[SmartApSelectionText] Assignation done in: " + (System.currentTimeMillis()-time) + " ms");
        System.out.println("\033[K\r[SmartApSelectionText] ====================");
        System.out.println("\033[K\r");
        Thread.sleep(SMARTAP_TEXT_PARAMS.pause); // If a pause or a period is needed
        System.out.print("\033[K\r\n\033[K\r\n\033[K\r\n\033[K\r\n\033[K\r\n\033[K\r\n\033[K\r\n\033[K\r\n\033[K\r\n\033[0;0H"); // Clear lines above and return to console 0,0
      } catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
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

  private double calculateT2(int numberOfStas, double tValue){
    double cwMin = 15.0;
    double slot = 0.000009;
    double result = tValue;

    if(numberOfStas>0){

      double pcValue = 1-Math.pow(1-(1/cwMin),numberOfStas);
      double tCont = (cwMin/2)*slot*(1+pcValue)/(2*(numberOfStas+1));

      result = tValue + tCont;

    }
    return result;
  }

  private double[] getTransmissionTime(double avgRate){ // Returns transmission times to calculate THavg

    double[] result;

    if(avgRate==54000.0){ // If higher value not reached, we use the next lower values
      result = new double[]{326.0,228.0};
      return result;
    }else if (avgRate>=48000.0){
      result = new double[]{354.0,256.0};
      return result;
    }else if (avgRate>=36000.0){
      result = new double[]{442.0,344.0};
      return result;
    }else if (avgRate>=24000.0){
      result = new double[]{610.0,512.0};
      return result;
    }else if (avgRate>=18000.0){
      result = new double[]{786.0,684.0};
      return result;
    }else if (avgRate>=12000.0){
      result = new double[]{1126.0,1024.0};
      return result;
    }else if (avgRate>=9000.0){
      result = new double[]{1478.0,1364.0};
      return result;
    }else { // 6 Mbps
      result = new double[]{2158.0,2044.0};
      return result;
    }
  }

  private double getOFDMRates(double SNR){ // Returns ODFM rates to calculate THavg
	
	double result = 0.0;
	
	if(SNR>21.0){ // If higher value not reached, we use the next lower values
		result = 54000.0;
		return result;
	}else if (SNR>=20.0){
		result = 48000.0;
		return result;
	}else if (SNR>=16.0){
		result = 36000.0;
		return result;
	}else if (SNR>=12.0){
		result = 24000.0;
		return result;
	}else if (SNR>=9.0){
		result = 18000.0;
		return result;
	}else if (SNR>=7.0){
		result = 12000.0;
		return result;
	}else if (SNR>=5.0){
		result = 9000.0;
		return result;
	}else if (SNR>=4.0){
		result = 6000.0;
		return result;
	}else { // Less than 4 dB => 0.0
		return result;
	}
  }

  private double calculateFittingnessFactor(double Rreq, double Rb){

    double shaping = 5, shaping_k = 1, shaping_mine = 1.3, ff = 0;

    if(Math.abs(Rb) > 1e-6){
      double U = Math.pow(Rb * shaping_mine/Rreq, shaping) / (1 + Math.pow(Rb*shaping_mine/Rreq, shaping));
      double lambda = 1 - Math.pow(Math.E, -shaping_k / (Math.pow(shaping-1, 1/shaping) + Math.pow(shaping-1, (1-shaping)/shaping)));
      ff = (1 - Math.pow(Math.E, -shaping_k * U / (Rb * shaping_mine / Rreq))) / lambda;
    }
    return ff;
  }

  private Map<MACAddress, InetAddress> simpleBalancerAlgorithm(Map<MACAddress, Double[]> rssiData, InetAddress[] agentsArray, HashSet<OdinClient> clients, Double threshold){ // Print load in each AP and returns array of agents to assign

    int ind_aux = 0;
    int agent_index = 0;
    int max_index = 0;
    int[] numStasPerAgent = new int[agentsArray.length];
    boolean orderHandoff = false;
    Map<MACAddress, InetAddress> arrayHandoff = new HashMap<MACAddress, InetAddress> ();

    HashSet<OdinClient> clients_Balancer;

    int maxStas = 0;
    int minStas = Integer.MAX_VALUE;
    int numberOfAgentsAvailable = 0;
    int num_clients = clients.size();
    

    for (InetAddress agentAddrBalancer: agentsArray) { // Create array with number of STAs for each AP, find the one with lower number

      clients_Balancer = new HashSet<OdinClient>(getClientsFromAgent(agentAddrBalancer));

      int numberOfStas = clients_Balancer.size();
      
      boolean stasToMove = false;

      numStasPerAgent[ind_aux] = numberOfStas;
      
      for(MACAddress eth:rssiData.keySet()){ // If there is not a STA with enougth RSSI, not handoff
        Double[] client_dBm = rssiData.get(eth);
        if(client_dBm[ind_aux]>SMARTAP_TEXT_PARAMS.signal_threshold){
          stasToMove=true;
        }
      }

      if((numberOfStas <= minStas)&&(stasToMove)){
        minStas = numberOfStas;
        agent_index = ind_aux;
      }
      if(numberOfStas >= maxStas){
        maxStas = numberOfStas;
        max_index = ind_aux;
      }
      if(stasToMove)
        numberOfAgentsAvailable++;
      ind_aux++;
    }
    ind_aux = 0;
    float mean = (float)num_clients/numberOfAgentsAvailable;
    int meanStas = Math.round(mean);

    for (InetAddress agentAddrBalancer: agentsArray) { // Print APs and number of STAs associated at it

      if((ind_aux==agent_index)&&(numStasPerAgent[ind_aux]<meanStas)&&(maxStas>meanStas)){ // min<mean and max>mean try to handoff a STA
        System.out.print("[\033[48;5;88;1m  "+numStasPerAgent[ind_aux]+"   \033[00m]");
        orderHandoff = true;
      }else{
        System.out.print("[  "+numStasPerAgent[ind_aux]+"   ]");
      }
      ind_aux++;
    }
    OdinClient clientHandoff=null;
    if(orderHandoff){
      clients_Balancer = new HashSet<OdinClient>(getClientsFromAgent(agentsArray[max_index]));
      double maxRssi=-99.9;
      for (OdinClient oc: clients_Balancer) {
        Double[] client_dBm = new Double[num_agents];
        MACAddress eth = oc.getMacAddress();
        InetAddress clientAddr = oc.getIpAddress();
        if(clientAddr.equals(nullAddr))// If client not assigned, next one
          continue;
        client_dBm = rssiData.get(eth);
        if (client_dBm != null){
          if((client_dBm[agent_index]>=maxRssi)&&(client_dBm[agent_index]>SMARTAP_TEXT_PARAMS.signal_threshold)){
            maxRssi = client_dBm[agent_index];
            clientHandoff = oc;
          }
        }
      }
    }
    if(clientHandoff!=null){
      arrayHandoff.put(clientHandoff.getMacAddress(),agentsArray[agent_index]);
      System.out.print("\033[0;1m - Handoff ordered\033[00m");
    }
    return arrayHandoff;
  }

  /**
  * This method shows and stores detected flows
  *
  * @param oefd
  * @param cntx
  */
  private void handler (OdinEventFlowDetection oefd, FlowDetectionCallbackContext cntx) {
    
	InetAddress IPSrcAddress = null;
    InetAddress IPDstAddress = null;
    //InetAddress odinAgentAddr = null;
	
	try {
      IPSrcAddress = InetAddress.getByName(cntx.IPSrcAddress);
      IPDstAddress = InetAddress.getByName(cntx.IPDstAddress);
      //odinAgentAddr = InetAddress.getByName(cntx.odinAgentAddr);
    } catch (UnknownHostException e) {
      e.printStackTrace();
    }
    
    DetectedFlow flowDetected = new DetectedFlow(IPSrcAddress,IPDstAddress,cntx.protocol,cntx.SrcPort,cntx.DstPort,cntx.odinAgentAddr,this.nonVipAPAddr,System.currentTimeMillis()) ;
    
    this.flowsReceived.put(IPSrcAddress, flowDetected);
  }

  public class DetectedFlow {
		public InetAddress IPSrcAddress;
		public InetAddress IPDstAddress;
		public int protocol;
		public int SrcPort;
		public int DstPort;
		public InetAddress odinAgentAddr;
		public InetAddress lastAgentAddr;
		public long timeStamp;

		public DetectedFlow (InetAddress IPSrcAddress, InetAddress IPDstAddress, int protocol, int SrcPort, int DstPort, InetAddress odinAgentAddr, InetAddress lastAgentAddr, long timeStamp) {
			this.IPSrcAddress = IPSrcAddress;
            this.IPDstAddress = IPDstAddress;
            this.protocol = protocol;
            this.SrcPort = SrcPort;
            this.DstPort = DstPort;
            this.odinAgentAddr = odinAgentAddr;
            this.lastAgentAddr = lastAgentAddr;
            this.timeStamp = timeStamp;
		}
	}

  // Print the load of the agents
  private void printAgentsLoad(InetAddress[] agentsArray,InetAddress vipAgent){ // Print load in each AP

    int ind_aux = 0;
    int[] numStasPerAgent = new int[agentsArray.length];

    HashSet<OdinClient> clients_AP;

    for (InetAddress agentAddrAP: agentsArray) { // Create array with number of STAs for each AP

      clients_AP = new HashSet<OdinClient>(getClientsFromAgent(agentAddrAP));

      int numberOfStas = clients_AP.size();

      numStasPerAgent[ind_aux] = numberOfStas;
      
      ind_aux++;
    }
    ind_aux = 0;

    for (InetAddress agentAddrAP: agentsArray) { // Print APs and number of STAs associated at it

      if(vipAgent.equals(agentAddrAP)){ // VIP agent
        if(numStasPerAgent[ind_aux]>0){
          System.out.print("[\033[48;5;3;1m  "+numStasPerAgent[ind_aux]+"   \033[00m]");
        }else{
          System.out.print("[\033[48;5;94m  "+numStasPerAgent[ind_aux]+"   \033[00m]");
        }
      }else{
        System.out.print("[  "+numStasPerAgent[ind_aux]+"   ]");
      }
      ind_aux++;
    }
  }

  private Map<MACAddress, InetAddress> jainsFairnessIndex(Map<MACAddress, Double[]> rssiData, InetAddress[] agentsArray, HashSet<OdinClient> clients, Double threshold){ // Print load in each AP and returns array of agents to assign

    int ind_aux = 0;
    int agent_index = 0;
    int[] numStasPerAgent = new int[agentsArray.length];
    boolean orderHandoff = false;
    Map<MACAddress, InetAddress> arrayHandoff = new HashMap<MACAddress, InetAddress> ();
    Map<InetAddress, Integer> agentIndex = new HashMap<InetAddress, Integer> ();
  
    HashSet<OdinClient> clients_Balancer;

    int num_clients = clients.size();
    
    for (InetAddress agentAddrBalancer: agentsArray) { // Create array with number of STAs for each AP and print it

      clients_Balancer = new HashSet<OdinClient>(getClientsFromAgent(agentAddrBalancer));

      int numberOfStas = clients_Balancer.size();

      numStasPerAgent[ind_aux] = numberOfStas;
    
      System.out.print("[  "+numberOfStas+"   ]");
    
      agentIndex.put(agentAddrBalancer,ind_aux);

      ind_aux++;
    }
    System.out.println("");
    
    for (OdinClient oc: clients) { // For each STA
      
      Double[] client_dBm = new Double[num_agents];
      MACAddress eth = oc.getMacAddress();
      InetAddress clientAddr = oc.getIpAddress();
      InetAddress clientAgent = oc.getLvap().getAgent().getIpAddress();
      int agent_index_assoc = agentIndex.get(clientAgent);
      double maxFI = 0;
      int index_maxFI = 0;
      
      
      Double[] fairnessIndex = new Double[num_agents];
      
          if(clientAddr.equals(nullAddr))// If client not assigned, next one
            continue;
        
          client_dBm = rssiData.get(eth);
      
          if (client_dBm != null){
        
          for (InetAddress agentAddrBalancer: agentsArray) { // For each AP
        
            ind_aux = 0;
            double sum = 0;
      
          if(clientAgent.equals(agentAddrBalancer)){ // numSTAs not changed
          
            for(int stas: numStasPerAgent){
              
              sum = sum + Math.pow(stas, 2);
            
            }
            
            fairnessIndex[agentIndex.get(agentAddrBalancer)] = num_clients / (num_agents*sum);
            
   
          }else{ // numSTAs changed
          
            agent_index = agentIndex.get(agentAddrBalancer);
          
            for(int stas: numStasPerAgent){
              
              if(agent_index == ind_aux){
                sum = sum + Math.pow(stas+1, 2);
              }else if(agent_index_assoc == ind_aux){
                sum = sum + Math.pow(stas-1, 2);
              }else{
                sum = sum + Math.pow(stas, 2);
              }
              
              ind_aux++;
            
            }
            
            fairnessIndex[agentIndex.get(agentAddrBalancer)] = num_clients / (num_agents*sum);

          }
          if((fairnessIndex[agentIndex.get(agentAddrBalancer)]>maxFI)&&(client_dBm[agentIndex.get(agentAddrBalancer)]>SMARTAP_TEXT_PARAMS.signal_threshold)){
            maxFI = fairnessIndex[agentIndex.get(agentAddrBalancer)];
            index_maxFI = agentIndex.get(agentAddrBalancer);
          }
        }
        
        ind_aux = 0;
        
        System.out.print("\033[K\r[SmartApSelectionText] ");
        for (Double fair_index: fairnessIndex) {
          
          if(ind_aux==agent_index_assoc){ // Green  
            System.out.print("[\033[48;5;29;1m " + String.format("%.2f",fair_index)+" \033[00m]");
          }else if(ind_aux==index_maxFI){ // Red
            System.out.print("[\033[48;5;88m " + String.format("%.2f",fair_index)+" \033[00m]");
          }else{ // Other
            System.out.print("[ " + String.format("%.2f",fair_index)+" ]");
          }
          ind_aux++;
              }
        System.out.print(" - "+clientAddr);
        if((client_dBm[index_maxFI]>SMARTAP_TEXT_PARAMS.signal_threshold)&&(index_maxFI!=agent_index_assoc)){
          arrayHandoff.put(eth,agentsArray[index_maxFI]);
          System.out.println("\033[0;1m - Handoff ordered\033[00m");
          break; // FIXME: allow several handoffs ordered at the same time
        }else{
          System.out.println("");
        }
      }
    }
  
    return arrayHandoff;
  }

}
