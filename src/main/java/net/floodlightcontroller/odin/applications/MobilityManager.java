package net.floodlightcontroller.odin.applications;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.math.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.odin.master.OdinApplication;

import net.floodlightcontroller.odin.master.NotificationCallback;
import net.floodlightcontroller.odin.master.NotificationCallbackContext;
import net.floodlightcontroller.odin.master.OdinClient;
import net.floodlightcontroller.odin.master.OdinEventSubscription;
import net.floodlightcontroller.odin.master.OdinMaster;
import net.floodlightcontroller.odin.master.OdinMaster.MobilityParams;
import net.floodlightcontroller.odin.master.OdinEventSubscription.Relation;
import net.floodlightcontroller.util.MACAddress;

public class MobilityManager extends OdinApplication {
  
  private final int debugLevel = 1;
  
	protected static Logger log = LoggerFactory.getLogger(MobilityManager.class);
	/* A table including each client and its mobility statistics */
	private ConcurrentMap<MACAddress, MobilityStats> clientMap = new ConcurrentHashMap<MACAddress, MobilityStats> ();
	private final String STA; 						// Handle a mac or all STAs ("*")
	private final String VALUE; 					// Parameter to measure (signal, noise, rate, etc.)
	private boolean scan; 							// For testing only once
	private MobilityParams MOBILITY_PARAMS;			// Mobility parameters imported from poolfile

	public MobilityManager () {
		/*this.STA = "40:A5:EF:05:9B:A0";*/
		this.STA = "*";
		this.VALUE = "signal";
		this.scan = true;
	}
	
	
	/**
	 * Condition for a hand off
	 *
	 * Example of params in poolfile imported in MOBILITY_PARAMS:
	 *
	 * MOBILITY_PARAMS.HYSTERESIS_THRESHOLD = 15;
	 * MOBILITY_PARAMS.SIGNAL_THRESHOLD = -56;
	 * MOBILITY_PARAMS.NUMBER_OF_TRIGGERS = 5;  
	 * MOBILITY_PARAMS.TIME_RESET_TRIGGER = 1;
	 *
	 * With these parameters a hand off will start when:
	 *
	 * At least 5 packets below -56dBm have been received from a specific client during 1000 ms, and a previous hand off has not happened in the last 15000 ms
	 *
	 */

	/**
	 * Register subscriptions
	 */
	private void init () {
    if (debugLevel >= 1) {
      System.out.println("[MobilityManager] Starting 'init()'");
    }     
	  
		OdinEventSubscription oes = new OdinEventSubscription();
		/* FIXME: Add something in order to subscribe more than one STA */
		oes.setSubscription(this.STA, this.VALUE, Relation.LESSER_THAN, this.MOBILITY_PARAMS.signal_threshold); 
		NotificationCallback cb = new NotificationCallback() {
			@Override
			public void exec(OdinEventSubscription oes, NotificationCallbackContext cntx) {
				if (scan == true) // For testing only once
					handler(oes, cntx);
			}
		};
		/* Before executing this line, make sure the agents declared in poolfile are started */	
		registerSubscription(oes, cb);
		
    if (debugLevel >= 1) {
      System.out.println("[MobilityManager] Subscriptions registered");
    }
		
    //log.info("MobilityManager: register"); 
	}

	@Override
	public void run() {

		this.MOBILITY_PARAMS = getMobilityParams ();
		/* When the application runs, you need some time to start the agents */
		this.giveTime(this.MOBILITY_PARAMS.time_to_start);
		//this.channelAssignment();
		//this.giveTime(10000);
		//setAgentTimeout(10000);
		init ();
	}
	
	/**
	 * This method will handoff a client in the event of its
	 * agent having failed.
	 *
	 * @param oes
	 * @param cntx
	 */
	private void handler (OdinEventSubscription oes, NotificationCallbackContext cntx) {
		OdinClient client = getClientFromHwAddress(cntx.clientHwAddress);
		long lastScanningResult = 0;
		long greaterscanningresult = 0;
		
		double client_signal = 0.0;
		long client_signal_dBm = 0;
		double client_average = 0.0;
		long client_average_dBm = 0;
		int client_triggers = 0;
		
		/*
		log.info("\n*\n*\n*\n*\n*\n*");
		log.info("MobilityManager: publish received from " + cntx.clientHwAddress
                                        + " in agent " + cntx.agent.getIpAddress());*/

    if (debugLevel >= 1) {
      System.out.println("[MobilityManager] publish received from agent " + cntx.clientHwAddress + " in agent " + cntx.agent.getIpAddress());
    }   
		/* The client is not registered in this controller, exit */
		if (client == null) {
	    if (debugLevel >= 1) {
	      System.out.println("[MobilityManager] The agent is not registered in this controller");
	    }  
	    return;
		}

		long currentTimestamp = System.currentTimeMillis();
		// Assign mobility statistics object if not already done
		// add an entry in the clientMap table for this client MAC
		// put the statistics in the table: value of the parameter, timestamp, timestamp, agent, scanning result, average power and number of triggers
		if (!clientMap.containsKey(cntx.clientHwAddress)) {
			clientMap.put(cntx.clientHwAddress, new MobilityStats(cntx.value, currentTimestamp, currentTimestamp, cntx.agent.getIpAddress(), cntx.value, cntx.client_average, cntx.client_triggers));
		}
		else clientMap.put(cntx.clientHwAddress, new MobilityStats(cntx.value, currentTimestamp, clientMap.get(cntx.clientHwAddress).assignmentTimestamp, cntx.agent.getIpAddress(), clientMap.get(cntx.clientHwAddress).scanningResult, clientMap.get(cntx.clientHwAddress).client_average, clientMap.get(cntx.clientHwAddress).client_triggers));
			 
		// get the statistics of that client
		MobilityStats stats = clientMap.get(cntx.clientHwAddress);
		
    if (debugLevel >= 1) {
      System.out.println("[MobilityManager] Client statistics. RSSI: " + clientMap.get(cntx.clientHwAddress).signalStrength );
    }
    
		/* Now, handoff */
		
		// The client is associated to Odin (it has an LVAP), but it does not have an associated agent
		// If client hasn't been assigned an agent, associate it to the current AP
		if (client.getLvap().getAgent() == null) {
			log.info("MobilityManager: client hasn't been asigned an agent: handing off client " + cntx.clientHwAddress
					+ " to agent " + stats.agentAddr + " at " + System.currentTimeMillis());

	    if (debugLevel >= 1) {
	      System.out.println("[MobilityManager] client hasn't been asigned an agent: handing off client " + cntx.clientHwAddress
	          + " to agent " + stats.agentAddr + " at " + System.currentTimeMillis());
	    }
			
			handoffClientToAp(cntx.clientHwAddress, stats.agentAddr);
			updateStatsWithReassignment (stats, cntx.value, currentTimestamp, stats.agentAddr, stats.scanningResult);
			clientMap.put(cntx.clientHwAddress,stats);
			return;
		}
		
		// Check for out-of-range client
		// a client has sent nothing during a certain time
		if ((currentTimestamp - stats.lastHeard) > MOBILITY_PARAMS.idle_client_threshold) {
			log.info("MobilityManager: client with MAC address " + cntx.clientHwAddress
					+ " was idle longer than " + MOBILITY_PARAMS.idle_client_threshold/1000 + " sec -> Reassociating it to agent " + stats.agentAddr);
			handoffClientToAp(cntx.clientHwAddress, stats.agentAddr);
			updateStatsWithReassignment (stats, cntx.value, currentTimestamp, stats.agentAddr, stats.scanningResult);
			clientMap.put(cntx.clientHwAddress,stats);
			return;
		}
		
		if ((currentTimestamp - stats.lastHeard) > MOBILITY_PARAMS.time_reset_triggers) {
            log.info("MobilityManager: Time threshold consumed");
            updateStatsScans(stats,currentTimestamp, 0, 0);
            clientMap.put(cntx.clientHwAddress,stats);
		}
		
		// this notification is from the agent that is hosting the client's LVAP, then
		// scan, update MobilityStats and handoff.
		if (client.getLvap().getAgent().getIpAddress().equals(cntx.agent.getIpAddress())) {
			
	    if (debugLevel >= 1) {
	      System.out.println("[MobilityManager] The notification is from the agent " + cntx.agent.getIpAddress() 
	        + " that is hosting the client" );
	    }
			
			/* Scan and update statistics */
			
			client_signal_dBm = stats.signalStrength - 256;
			client_average_dBm = stats.client_average - 256;
			client_triggers = stats.client_triggers;
			//log.info("MobilityManager: Triggers: "+ client_triggers);
			
			//log.info("MobilityManager: STA current power in this client: "+ stats.signalStrength + " (" + client_signal_dBm + "dBm)");

      if (debugLevel >= 1) {
        System.out.println("[MobilityManager] Triggers: "+ client_triggers);
        System.out.println("[MobilityManager] STA current power in this client: "+ stats.signalStrength + " (" + client_signal_dBm + "dBm)");
      }
			
			if (client_triggers != MOBILITY_PARAMS.number_of_triggers){
				
				client_signal = Math.pow(10.0, (client_signal_dBm) / 10.0); // Linear power
				//log.info("client_signal: "+ client_signal);
				client_average = Math.pow(10.0, (client_average_dBm) / 10.0); // Linear power average
				//log.info("client_average: "+ client_average);
				client_average = client_average  + ((client_signal - client_average)/( client_triggers +1)); // Cumulative moving average
				//log.info("client_average: "+ client_average);
				client_average_dBm = Math.round(10.0*Math.log10(client_average)); //Average power in dBm
        //log.info("client_average_dBm: "+ client_average_dBm);
        client_triggers++; // Increase number of triggers that will be used to calculate average power
        if (debugLevel >= 1) {
          System.out.println("[MobilityManager] client_signal: "+ client_signal);
          System.out.println("[MobilityManager] client_average linear: "+ client_average);
          System.out.println("[MobilityManager] client_average_dbm: "+ client_average_dBm);
          System.out.println("[MobilityManager] client_triggers: "+ client_triggers);
        }
        updateStatsScans(stats, currentTimestamp, client_average_dBm + 256, client_triggers);
        clientMap.put(cntx.clientHwAddress,stats);
        //log.info("MobilityManager: STA average power in this client: "+ stats.client_average + " (" + client_average_dBm + "dBm)");
        //log.info("MobilityManager: Triggers: "+ stats.client_triggers);
        if (debugLevel >= 1) {
          System.out.println("[MobilityManager] STA average power in this client:  "+ stats.client_average + " (" + client_average_dBm + "dBm");
          System.out.println("[MobilityManager] Triggers" + stats.client_triggers);
        }
        
				return;
				
			} else { // client_triggers == MOBILITY_PARAMS.number_of_triggers
				
				updateStatsScans(stats,currentTimestamp, 0, 0);
				clientMap.put(cntx.clientHwAddress,stats);
				
				// Don't bother if we're not within hysteresis period
        if (currentTimestamp - stats.assignmentTimestamp < MOBILITY_PARAMS.hysteresis_threshold) {
          if (debugLevel >= 1) {
            System.out.println("[MobilityManager] hystheresis threshold not reached ("+ MOBILITY_PARAMS.hysteresis_threshold + ")");
          }          
          return;
        }
        
        log.info("MobilityManager: Scan triggered with average power: "+ (client_average_dBm + 256) + " (" + client_average_dBm + "dBm)");
        
        if (debugLevel >= 1) {
          System.out.println("[MobilityManager] Scan triggered with average power: "+ (client_average_dBm + 256) + " (" + client_average_dBm + "dBm)");
        }
			}
			
			for (InetAddress agentAddr: getAgents()) { // FIXME: scan for nearby agents only 
				// This is the agent where the STA is associated, so we don't scan
				if (cntx.agent.getIpAddress().equals(agentAddr)) {
					log.info("MobilityManager: Do not Scan client " + cntx.clientHwAddress + " in agent (Skip same AP) " + agentAddr + " and channel " + getChannelFromAgent(agentAddr));
	        if (debugLevel >= 1) {
	          System.out.println("[MobilityManager] Do not Scan client " + cntx.clientHwAddress + " in agent (Skip same AP) " + agentAddr + " and channel " + getChannelFromAgent(agentAddr));
	        }
					continue; // Skip same AP
				}
				// Scanning in the rest of APs
				else {
					log.info("MobilityManager: Scanning client " + cntx.clientHwAddress + " in agent " + agentAddr + " and channel " + getChannelFromAgent(cntx.agent.getIpAddress()));
					if (debugLevel >= 1) {
            System.out.println("MobilityManager: Scanning client " + cntx.clientHwAddress + " in agent " + agentAddr + " and channel " + getChannelFromAgent(cntx.agent.getIpAddress()));
					}
					// Send the scanning request to the agent
					
          lastScanningResult = scanClientFromAgent(agentAddr, cntx.clientHwAddress, getChannelFromAgent(cntx.agent.getIpAddress()), this.MOBILITY_PARAMS.scanning_time);
          //log.info("MobilityManager: Last Scanning Result: "+lastScanningResult);
                    
          //scan = false; // For testing only once
					//if (lastScanningResult >= 50) { // testing
						
					if (lastScanningResult > stats.signalStrength) {
						//greaterscanningresult = stats.signalStrength; 
						greaterscanningresult = lastScanningResult;// 
						updateStatsWithReassignment(stats, lastScanningResult, currentTimestamp, agentAddr, greaterscanningresult);
					}
					else if (greaterscanningresult < lastScanningResult) { // 
					  greaterscanningresult = lastScanningResult;
					}
        }
        //log.info("MobilityManager: Higher Scanning result: " + greaterscanningresult);
        log.info("MobilityManager: Scanned client " + cntx.clientHwAddress + " in agent " + agentAddr + " and channel " + getChannelFromAgent(cntx.agent.getIpAddress()) + " with power " + lastScanningResult);
        if (debugLevel >= 1) {
          System.out.println("[MobilityManager] Scanned client " + cntx.clientHwAddress + " in agent " + agentAddr + " and channel " + getChannelFromAgent(cntx.agent.getIpAddress()) + " with power " + lastScanningResult);
        }
      }
			
			if (cntx.agent.getIpAddress().equals(stats.agentAddr)) {
				stats.scanningResult = greaterscanningresult;
				clientMap.put(cntx.clientHwAddress,stats);
				log.info("MobilityManager: no hand off");
				if (debugLevel >= 1) {
          System.out.println("[MobilityManager] no hand off");
				}
				return;
			}
			
			log.info("MobilityManager: signal strength: new = " + stats.signalStrength + " old = " + cntx.value + " handing off client " + cntx.clientHwAddress
						+ " to agent " + stats.agentAddr);
			if (debugLevel >= 1) {
			  System.out.println("[MobilityManager] signal strength: new = " + stats.signalStrength + " old = " + cntx.value + " handing off client " + cntx.clientHwAddress
           + " to agent " + stats.agentAddr);
			}
			handoffClientToAp(cntx.clientHwAddress, stats.agentAddr);
			clientMap.put(cntx.clientHwAddress,stats);
			//log.info("\n*\n*\n*\n*\n*\n*");
      if (debugLevel >= 1) {
        System.out.println("[MobilityManager] ending the handler");
      }
			return;
		}
	}
	
	/**
	 * This method will update statistics
	 *
	 * @param stats
	 * @param signalValue
	 * @param now
	 * @param agentAddr
	 * @param scanningResult
	 */
	private void updateStatsWithReassignment (MobilityStats stats, long signalValue, long now, InetAddress agentAddr, long scanningResult) {
		stats.signalStrength = signalValue;
		stats.lastHeard = now;
		stats.assignmentTimestamp = now;
		stats.agentAddr = agentAddr;
		stats.scanningResult = scanningResult;
		
	}
	
	
	/**
	 * This method will only update when trigger
	 *
	 * @param stats
	 * @param average
	 * @param triggers
	 */
	private void updateStatsScans (MobilityStats stats, long now, long average, int triggers) {
        stats.lastHeard = now;
		stats.client_average = average;
		stats.client_triggers = triggers;
	}
	
	
	/**
	 * Sleep
	 *
	 * @param time
	 */
	private void giveTime (int time) {
		try {
					Thread.sleep(time);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
	}
		
	/**
	 * It will be a method for channel assignment
	 *
	 * FIXME: Do it in a suitable way
	 */
	private void channelAssignment () {
		for (InetAddress agentAddr: getAgents()) {
			log.info("MobilityManager: Agent IP: " + agentAddr.getHostAddress());
			if (agentAddr.getHostAddress().equals("192.168.1.9")){
				log.info ("MobilityManager: Agent channel: " + getChannelFromAgent(agentAddr));
				setChannelToAgent(agentAddr, 1);
				log.info ("MobilityManager: Agent channel: " + getChannelFromAgent(agentAddr));
			}
			if (agentAddr.getHostAddress().equals("192.168.1.10")){
				log.info ("MobilityManager: Agent channel: " + getChannelFromAgent(agentAddr));
				setChannelToAgent(agentAddr, 11);
				log.info ("MobilityManager: Agent channel: " + getChannelFromAgent(agentAddr));
			}
			
		}
	}

	private class MobilityStats {
		public long signalStrength;
		public long lastHeard;				// timestamp where it was heard the last time
		public long assignmentTimestamp;	// timestamp it was assigned
		public InetAddress agentAddr;
		public long scanningResult;
		public long client_average;				// average power
		public int client_triggers;					// number of triggers to calculate average power

		public MobilityStats (long signalStrength, long lastHeard, long assignmentTimestamp, InetAddress agentAddr, long scanningResult, long average, int triggers) {
			this.signalStrength = signalStrength;
			this.lastHeard = lastHeard;
			this.assignmentTimestamp = assignmentTimestamp;
			this.agentAddr = agentAddr;
			this.scanningResult = scanningResult;
			this.client_average = average;
			this.client_triggers = triggers;
		}
	}
}
