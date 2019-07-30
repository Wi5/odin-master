package net.floodlightcontroller.odin.applications;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import net.floodlightcontroller.odin.master.OdinApplication;
import net.floodlightcontroller.odin.master.OdinClient;
import net.floodlightcontroller.util.MACAddress;

import net.floodlightcontroller.odin.master.OdinMaster.ScannParams;

import org.apache.commons.io.output.TeeOutputStream;

public class ShowMatrixOfDistancedBs extends OdinApplication {

// IMPORTANT: this application only works if all the agents in the
//poolfile are activated before the end of the INITIAL_INTERVAL.
// Otherwise, the application looks for an object that does not exist
//and gets stopped

// SSID to scan
private final String SCANNED_SSID = "odin_init";

// Scann params
private ScannParams SCANN_PARAMS;

// Scanning agents
Map<InetAddress, Integer> scanningAgents = new HashMap<InetAddress, Integer> ();
int result; // Result for scanning

// Matrix
private String matrix = "";
private String avg_dB = "";


@Override
public void run() {
	
  System.out.println("[ShowMatrixOfDistancedBs] Starting application");
  
	this.SCANN_PARAMS = getMatrixParams();
	System.out.println("[ShowMatrixOfDistancedBs] Application params gathered");
	
  try {
    System.out.println("[ShowMatrixOfDistancedBs] Sleeping for " + SCANN_PARAMS.time_to_start + " ms (time to start)"); 
		Thread.sleep(SCANN_PARAMS.time_to_start);
	} catch (InterruptedException e) {
	  e.printStackTrace();
	}
	
  System.out.println("[ShowMatrixOfDistancedBs] Application started");
  
	while (true) {
    try {
      System.out.println("[ShowMatrixOfDistancedBs] Sleeping for " + SCANN_PARAMS.reporting_period + " ms (reporting period)"); 
      Thread.sleep(SCANN_PARAMS.reporting_period);
      matrix = "";
        		
  		System.out.println("[ShowMatrixOfDistancedBs] Matrix of Distance"); 
  		System.out.println("[ShowMatrixOfDistancedBs] =================="); 
  		System.out.println("[ShowMatrixOfDistancedBs]");

  		//For channel SCANNING_CHANNEL
  		System.out.println("[ShowMatrixOfDistancedBs] Scanning channel " + SCANN_PARAMS.channel);
  		System.out.println("[ShowMatrixOfDistancedBs]");

  		// go through all the agents. each of them will be 'beaconAgentAddr'
  		for (InetAddress beaconAgentAddr: getAgents()) {
  		  scanningAgents.clear();
  		  System.out.println("[ShowMatrixOfDistancedBs] Agent that will send measurement beacons: " + beaconAgentAddr);	
			
  		  // For each Agent (not the "beaconAgentAddr", i.e. the one that is sending measurement beacons)
  		  //System.out.println("[ShowMatrixOfDistancedBs] Request for scanning during the interval of  " + SCANN_PARAMS.scanning_interval + " ms in SSID " + SCANNED_SSID);	
  		  for (InetAddress agentAddr: getAgents()) {
	  			if (agentAddr != beaconAgentAddr) {
	          // Request statistics from this agent
	  			  System.out.println("[ShowMatrixOfDistancedBs] Agent " + agentAddr + " requested to scan during the interval of  " + SCANN_PARAMS.scanning_interval + " ms for SSID " + SCANNED_SSID);
	  			  // the next line sends a write Scan_APs to this agent
	  			  result = requestScannedStationsStatsFromAgent(agentAddr, SCANN_PARAMS.channel, SCANNED_SSID);
	  			  System.out.println("[ShowMatrixOfDistancedBs] Result of WRITE.scan_APs: " + result);
	  			  // fill the hash table
	  			  scanningAgents.put(agentAddr, result);
	  			}
  		  }					
				
  			// Request the "beaconAgentAddr" agent to send measurement beacons
  		  System.out.println("[ShowMatrixOfDistancedBs] Agent " + beaconAgentAddr + " requested to send measurement beacons indefinitely with SSID " + SCANNED_SSID);
  			if (requestSendMesurementBeaconFromAgent(beaconAgentAddr, SCANN_PARAMS.channel, SCANNED_SSID) == 0) {
					System.out.println("[ShowMatrixOfDistancedBs] Agent BUSY during measurement beacon operation");
					continue;				
  			}
        
  			System.out.println("[ShowMatrixOfDistancedBs] Agent " + beaconAgentAddr + " will start sending measurement beacons from now on");

  			// sleep while the measurement beacons are being sent by
  			//beaconAgentAddr and scanned by the rest of agents
  			try {
  			  System.out.println("[ShowMatrixOfDistancedBs] Waiting for scanning interval + added time: " + SCANN_PARAMS.scanning_interval + SCANN_PARAMS.added_time + " s");
  			  Thread.sleep(SCANN_PARAMS.scanning_interval + SCANN_PARAMS.added_time);
				} 
  			catch (InterruptedException e) {
					e.printStackTrace();
				}
			
  			// Stop sending meesurement beacons
        System.out.println("[ShowMatrixOfDistancedBs] Telling agent " + beaconAgentAddr + " to stop sending measurement beacons now");
        // the next command will send "WRITE.scanning_flags 0 0 0" to the agent
  			stopSendMesurementBeaconFromAgent(beaconAgentAddr);
			
  			matrix = matrix + beaconAgentAddr.toString().substring(1);

  			// go through the agents that are not the beaconAgentAddr
  			//gathering their scanning results
  			for (InetAddress agentAddr: getAgents()) {			
  			  if (agentAddr != beaconAgentAddr) {

  			    System.out.println("[ShowMatrixOfDistancedBs] Gathering results:");
  			    System.out.println("[ShowMatrixOfDistancedBs]   Agent: " + agentAddr + " in channel " + SCANN_PARAMS.channel);

  			    // Reception distances
  			    if (scanningAgents.get(agentAddr) == 0) {
  			      // the agent was not contacted when scanning was requested. skip it
  			      System.out.println("[ShowMatrixOfDistancedBs] Agent BUSY during scanning operation");
  			      continue;				
  			    }
  			    
  			    Map<MACAddress, Map<String, String>> vals_rx = getScannedStationsStatsFromAgent(agentAddr,SCANNED_SSID);
  			    System.out.println("[ShowMatrixOfDistancedBs]    " + vals_rx.toString() );

  					// for each STA scanned by the Agent, i.e. each entry in vals_rx
  					for (Entry<MACAddress, Map<String, String>> vals_entry_rx: vals_rx.entrySet()) {
  					  // NOTE: the clients currently scanned MAY NOT be the same as the clients who have been associated		
  						MACAddress APHwAddr = vals_entry_rx.getKey();
  						avg_dB = vals_entry_rx.getValue().get("avg_signal");
  						System.out.println("\tAP MAC: " + APHwAddr);
  						System.out.println("\tavg signal: " + avg_dB + " dBm");
  						if(avg_dB.length()>6){
                matrix = matrix + "\t" + avg_dB.substring(0,6) + " dBm";
  						} else {
                matrix = matrix + "\t" + avg_dB + " dBm   ";
  						}
  					}

  				} else {
  				  // this is the beaconAgent, so print a line
            matrix = matrix + "\t----------";
  				}   
  			}
  			matrix = matrix + "\n";
  		}
  		//Print the matrix
  		System.out.println("[ShowMatrixOfDistancedBs] ==================");
      System.out.println(matrix);            
  		System.out.println("[ShowMatrixOfDistancedBs] ==================");	
  	  } catch (InterruptedException e) {
  	    e.printStackTrace();
  	  }
  	}
  }
}
