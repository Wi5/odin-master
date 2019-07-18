package net.floodlightcontroller.odin.master;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentSkipListSet;
import org.codehaus.jackson.map.annotate.JsonSerialize;
import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.U16;

import java.util.Collections;
import java.lang.*;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.util.MACAddress;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * 
 * OdinAgent class. Wi5 NOTE: we introduce a new variable 
 * channel to map the physical Wi-Fi channel used by the access point.
 * 
 * @author Lalith Suresh <suresh.lalith@gmail.com>
 */
@JsonSerialize(using=OdinAgentSerializer.class)
class OdinAgent implements IOdinAgent {

	protected static Logger log = LoggerFactory.getLogger(OdinAgent.class);

	// Connect to control socket on OdinAgent
	private Socket odinAgentSocket = null;
	private PrintWriter outBuf;
	private BufferedReader inBuf;
	private IOFSwitch ofSwitch;
	private InetAddress ipAddress;
	private long lastHeard;
	private int channel;
	private int lastScan;
	private int txpower;

	private ConcurrentSkipListSet<OdinClient> clientList = new ConcurrentSkipListSet<OdinClient>();

	// OdinAgent Handler strings. Wi5: We introduce handlers to manage APs channels
	private static final String READ_HANDLER_TABLE = "table";
	private static final String READ_HANDLER_TXSTATS = "txstats";
	private static final String READ_HANDLER_RXSTATS = "rxstats";
	private static final String READ_HANDLER_SPECTRAL_SCAN = "spectral_scan";
	private static final String READ_HANDLER_CHANNEL = "channel";
	private static final String READ_HANDLER_SCAN_CLIENT = "scan_client";
	private static final String READ_HANDLER_SCAN_APS = "scan_APs";
	private static final String READ_HANDLER_SCANING_FLAGS = "scanning_flags";
	private static final String READ_HANDLER_TXPOWER = "txpower";
	private static final String READ_HANDLER_STA_RSSI = "sta_rssi";
	private static final String WRITE_HANDLER_ADD_VAP = "add_vap";
	private static final String WRITE_HANDLER_SET_VAP = "set_vap";
	private static final String WRITE_HANDLER_REMOVE_VAP = "remove_vap";
	private static final String WRITE_HANDLER_SUBSCRIPTIONS = "subscriptions";
	private static final String WRITE_HANDLER_SEND_PROBE_RESPONSE = "send_probe_response";
	private static final String WRITE_HANDLER_SPECTRAL_SCAN = "spectral_scan";
	private static final String WRITE_HANDLER_CHANNEL = "channel";
	private static final String WRITE_HANDLER_CHANNEL_SWITCH_ANNOUNCEMENT = "channel_switch_announcement";
	private static final String WRITE_HANDLER_SCAN_CLIENT = "scan_client";
	private static final String WRITE_HANDLER_SCAN_APS = "scan_APs";
	private static final String WRITE_HANDLER_SEND_MEASUREMENT_BEACON = "send_measurement_beacon";
	private static final String WRITE_HANDLER_SCANING_FLAGS = "scanning_flags";
	private static final String ODIN_AGENT_ELEMENT = "odinagent";

	private final String detectionAgentIP = setDetectorIpAddress();
	private static final String DETECTION_AGENT_ELEMENT = "detectionagent";

	private final int TX_STAT_NUM_PROPERTIES = 8;
	private final int RX_STAT_NUM_PROPERTIES = 8;
	private final int MTX_DISTANCE_RX_STAT_NUM_PROPERTIES = 1;
	private final int ODIN_AGENT_PORT = 6777;


	/**
	 * Probably need a better identifier
	 *
	 * @return the agent's IP address
	 */
	public InetAddress getIpAddress() {
		return ipAddress;
	}

	/**
	 * Returns timestamp of last heartbeat from agent
	 *
	 * @return Timestamp
	 */
	public long getLastHeard() {
		return lastHeard;
	}


	/**
	 * Set the lastHeard timestamp of a client
	 *
	 * @param t  timestamp to update lastHeard value
	 */
	public void setLastHeard(long t) {
		this.lastHeard = t;
	}


	/**
	 * Probe the agent for a list of VAPs its hosting. This should only be used
	 * by the master when an agent registration to shield against master
	 * failures. The assumption is that when this is invoked, the controller has
	 * never heard about the agent before.
	 *
	 * @return a list of OdinClient entities on the agent
	 */
	public Set<OdinClient> getLvapsRemote() {
		ConcurrentSkipListSet<OdinClient> clients = new ConcurrentSkipListSet<OdinClient>();
		String handle = invokeReadHandler(READ_HANDLER_TABLE);

		if (handle == null) {
			return clients; // empty list
		}

		String tableList[] = handle.split("\n");

		for (String entry : tableList) {

			if (entry.equals(""))
				break;
						

			/*
			 * Every entry looks like this:
			 * properties:  [0]       [1]         [2]         [3, 4, 5...]
			 *           <sta_mac> <ipv4addr> <lvap bssid> <lvap ssid list>
			 *
			 */
			String properties[] = entry.split(" ");
			OdinClient oc;
			Lvap lvap;
			try {
				// First, get the list of all the SSIDs

				ArrayList<String> ssidList = new ArrayList<String>();
				for (int i = 3; i < properties.length; i++) {
					ssidList.add (properties[i]);
				}
				lvap =  new Lvap (MACAddress.valueOf(properties[2]), ssidList);
				oc = new OdinClient(MACAddress.valueOf(properties[0]),
						InetAddress.getByName(properties[1]), lvap);
				lvap.setAgent(this);
				clients.add(oc);

			} catch (UnknownHostException e) {
				e.printStackTrace();
			}
		}

		clientList = clients;

		return clients;
	}


	/**
	 * Return a list of LVAPs that the master knows this agent is hosting.
	 * Between the time an agent has crashed and the master detecting the crash,
	 * this can return stale values.
	 *
	 * @return a list of OdinClient entities on the agent
	 */
	public Set<OdinClient> getLvapsLocal() {
		return clientList;
	}

	/**
	 * Retrieve Tx-stats from the OdinAgent.
	 *
	 * @return A map of stations' MAC addresses to a map of properties and
	 *         values.
	 */
	public Map<MACAddress, Map<String, String>> getTxStats() {
		String stats = invokeReadHandler(READ_HANDLER_TXSTATS);

		Map<MACAddress, Map<String, String>> ret = new HashMap<MACAddress, Map<String, String>>();

		/*
		 * We basically get rows like this MAC_ADDR1 prop1:<value> prop2:<value>
		 * MAC_ADDR2 prop1:<value> prop2:<value>
		 */
		String arr[] = stats.split("\n");
		for (String elem : arr) {
			String row[] = elem.split(" ");

			if (row.length != TX_STAT_NUM_PROPERTIES + 1) {
				continue;
			}

			MACAddress eth = MACAddress.valueOf(row[0].toLowerCase());

			Map<String, String> innerMap = new HashMap<String, String>();

			for (int i = 1; i < TX_STAT_NUM_PROPERTIES + 1; i += 1) {
				innerMap.put(row[i].split(":")[0], row[i].split(":")[1]);
			}

			ret.put(eth, Collections.unmodifiableMap(innerMap));
		}

		return Collections.unmodifiableMap(ret);
	}

	/**
	 * Retrive Rx-stats from the OdinAgent.
	 *
	 * @return A map of stations' MAC addresses to a map of properties and
	 *         values.
	 */
	public Map<MACAddress, Map<String, String>> getRxStats() {
		String stats = invokeReadHandler(READ_HANDLER_RXSTATS);

		Map<MACAddress, Map<String, String>> ret = new HashMap<MACAddress, Map<String, String>>();

		/*
		 * We basically get rows like this MAC_ADDR1 prop1:<value> prop2:<value>
		 * MAC_ADDR2 prop1:<value> prop2:<value>
		 */
		String arr[] = stats.split("\n");
		for (String elem : arr) {
			String row[] = elem.split(" ");

			if (row.length != RX_STAT_NUM_PROPERTIES + 1) {
				continue;
			}
			if (row[1].split(":")[1].equals("0")) { // Avoid beacons
                continue;
			}

			MACAddress eth = MACAddress.valueOf(row[0].toLowerCase());

			Map<String, String> innerMap = new HashMap<String, String>();

			for (int i = 1; i < RX_STAT_NUM_PROPERTIES + 1; i += 1) {
				innerMap.put(row[i].split(":")[0], row[i].split(":")[1]);
			}

			ret.put(eth, Collections.unmodifiableMap(innerMap));
		}

		return Collections.unmodifiableMap(ret);
	}


	/**
	 * To be called only once, initialises a connection to the OdinAgent's
	 * control socket. We let the connection persist so as to save on
	 * setup/tear-down messages with every invocation of an agent. This will
	 * also help speedup handoffs.
	 *
	 * @param host Click based OdinAgent host
	 * @param port Click based OdinAgent's control socket port
	 * @return 0 on success, -1 otherwise
	 */
	public int init(InetAddress host) {

		OFFlowMod flow1 = new OFFlowMod();
		{
			OFMatch match = new OFMatch();
			//match.fromString("in_port=1,dl_type=0x0800");
			//match.fromString("in_port=1, dl_type=0x0800,nw_proto=17,tp_dst=68"); //port 68 used by DHCP client, 67 by server
			match.fromString("in_port=1");

			OFActionOutput actionOutput = new OFActionOutput ();
			actionOutput.setPort((short) 2);
			actionOutput.setLength((short) OFActionOutput.MINIMUM_LENGTH);

			List<OFAction> actionList = new ArrayList<OFAction>();
			actionList.add(actionOutput);

			flow1.setCookie(67);
			flow1.setPriority((short) 200);
			flow1.setMatch(match);
			flow1.setIdleTimeout((short) 0);
			flow1.setActions(actionList);
			flow1.setLength(U16.t(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
		}

		OFFlowMod flow2 = new OFFlowMod();
		{
			OFMatch match = new OFMatch();
			//match.fromString("in_port=2,dl_type=0x0800");
			//match.fromString("in_port=2, dl_type=0x0800,nw_proto=17,tp_dst=67"); //port 68 used by DHCP client, 67 by server
			match.fromString("in_port=2");

			OFActionOutput actionOutput = new OFActionOutput ();
			actionOutput.setPort((short) 1);
			actionOutput.setLength((short) OFActionOutput.MINIMUM_LENGTH);

			List<OFAction> actionList = new ArrayList<OFAction>();
			actionList.add(actionOutput);

			flow2.setCookie(67);
			flow2.setPriority((short) 200);
			flow2.setMatch(match);
			flow2.setIdleTimeout((short) 0);
			flow2.setActions(actionList);
			flow2.setLength(U16.t(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
		}

		OFFlowMod flow3 = new OFFlowMod();
		{
			OFMatch match = new OFMatch();
			match.fromString("dl_type=0x0800,nw_proto=17,tp_dst=68");

			OFActionOutput actionOutput = new OFActionOutput ();
			actionOutput.setPort(OFPort.OFPP_CONTROLLER.getValue());
			actionOutput.setLength((short) OFActionOutput.MINIMUM_LENGTH);
			actionOutput.setMaxLength((short)500);
			List<OFAction> actionList = new ArrayList<OFAction>();
			actionList.add(actionOutput);


			flow3.setCookie(67);
			flow3.setPriority((short) 300);
			flow3.setMatch(match);
			flow3.setIdleTimeout((short) 0);
			flow3.setActions(actionList);
			flow3.setLength(U16.t(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
		}

		//TODO: flow rule for local port (TNO-Unizar)
		/*OFFlowMod flow4 = new OFFlowMod();
		{
			OFMatch match = new OFMatch();
			//match.fromString("in_port=2,dl_type=0x0800");
			//match.fromString("in_port=2, dl_type=0x0800,nw_proto=17,tp_dst=67"); //port 68 used by DHCP client, 67 by server
			//TODO: also add match on source address 
			match.fromString("in_port=1,dl_type=0x0800,nw_dst=" + this.ipAddress + ",nw_proto=6,tp_dst=6777");

			OFActionOutput actionOutput = new OFActionOutput ();
			actionOutput.setPort(OFPort.OFPP_LOCAL.getValue());
			actionOutput.setLength((short) OFActionOutput.MINIMUM_LENGTH);

			List<OFAction> actionList = new ArrayList<OFAction>();
			actionList.add(actionOutput);

			flow4.setCookie(67);
			flow4.setPriority((short) 200);
			flow4.setMatch(match);
			flow4.setIdleTimeout((short) 0);
			flow4.setActions(actionList);
			flow4.setLength(U16.t(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
		}

		try {
			//ofSwitch.write(flow1, null);
			//ofSwitch.write(flow2, null);
			//ofSwitch.write(flow3, null);
			ofSwitch.write(flow4, null);
		} catch (IOException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}*/

		try {
			odinAgentSocket = new Socket(host.getHostAddress(), ODIN_AGENT_PORT);
			outBuf = new PrintWriter(odinAgentSocket.getOutputStream(), true);
			inBuf = new BufferedReader(new InputStreamReader(odinAgentSocket
					.getInputStream()));
			ipAddress = host;
		} catch (UnknownHostException e) {
			e.printStackTrace();
			return -1;
		} catch (IOException e) {
			e.printStackTrace();
			return -1;
		}

		return 0;
	}


	/**
	 * Get the IOFSwitch for this agent
	 *
	 * @return ofSwitch
	 */
	public IOFSwitch getSwitch() {
		return ofSwitch;
	}


	/**
	 * Set the IOFSwitch entity corresponding to this agent
	 *
	 * @param sw the IOFSwitch entity for this agent
	 */
	public void setSwitch(IOFSwitch sw) {
		ofSwitch = sw;
	}


	/**
	 * Remove a virtual access point from the AP corresponding to this agent
	 *
	 * @param staHwAddr The STA's ethernet address
	 */
	public void removeClientLvap(OdinClient oc) {
		invokeWriteHandler(WRITE_HANDLER_REMOVE_VAP, oc.getMacAddress()
				.toString());
		clientList.remove(oc);
	}


	/**
	 * Add a virtual access point to the AP corresponding to this agent
	 *
	 * @param oc OdinClient entity
	 */
	public void addClientLvap(OdinClient oc) {
		assert (oc.getLvap() != null);

		String ssidList = "";

		for (String ssid: oc.getLvap().getSsids()) {
			ssidList += " " + ssid;
		}

		invokeWriteHandler(WRITE_HANDLER_ADD_VAP, oc.getMacAddress().toString()
				+ " " + oc.getIpAddress().getHostAddress() + " "
				+ oc.getLvap().getBssid().toString() + ssidList);
		clientList.add(oc);
	}


	/**
	 * Update a virtual access point with possibly new IP, BSSID, or SSID
	 *
	 * @param oc OdinClient entity
	 */
	public void updateClientLvap(OdinClient oc) {
		assert (oc.getLvap() != null);

		String ssidList = "";

		for (String ssid: oc.getLvap().getSsids()) {
			ssidList += " " + ssid;
		}

		invokeWriteHandler(WRITE_HANDLER_SET_VAP, oc.getMacAddress().toString()
				+ " " + oc.getIpAddress().getHostAddress() + " "
				+ oc.getLvap().getBssid().toString() + ssidList);
	}


	/**
	 * Set subscriptions
	 *
	 * @param subscriptions
	 * @param t timestamp to update lastHeard value
	 */
	public void setSubscriptions(String subscriptionList) {
		invokeWriteHandler(WRITE_HANDLER_SUBSCRIPTIONS, subscriptionList);
	}


	/**
	 * Internal method to invoke a read handler on the OdinAgent
	 *
	 * @param handlerName OdinAgent handler
	 * @return read-handler string
	 */
	private synchronized String invokeReadHandler(String handlerName) {
		//log.info("[invokeReadHandler] Begin " + handlerName);
		//log.info("[invokeReadHandler] IP address of detection agent is " + this.detectionAgentIP);
		//log.info("[invokeReadHandler] IP address of agent is " + this.ipAddress);
		if (this.ipAddress.getHostAddress().equals(this.detectionAgentIP))
		   	outBuf.println("READ " + DETECTION_AGENT_ELEMENT + "." + handlerName);
		else outBuf.println("READ " + ODIN_AGENT_ELEMENT + "." + handlerName);
		
		String line = "";

		try {
			String data = null;
			while ((data = inBuf.readLine()).contains("DATA") == false) {
				// skip all the crap that the Click control
				// socket tells us
			}
			int numBytes = Integer.parseInt(data.split(" ")[1]);

			while (numBytes != 0) {
				numBytes--;
				char[] buf = new char[1];
				inBuf.read(buf);
				line = line + new String(buf);
			}
			//log.info("[invokeReadHandler] End " + handlerName + line);
			return line;
		} catch (IOException e) {
			e.printStackTrace();
		}
		//log.info("[invokeReadHandler] End " + handlerName);
		return null;
	}


	/**
	 * Internal method to invoke a write handler of the OdinAgent
	 *
	 * @param handlerName OdinAgent write handler name
	 * @param handlerText Write string
	 */
	private synchronized void invokeWriteHandler(String handlerName,
			String handlerText) {
		//log.info("[invokeWriteHandler] Begin " + handlerName);
		//log.info("[invokeWriteHandler] IP address of detection agent is " + this.detectionAgentIP);
		//log.info("[invokeWriteHandler] IP address of agent is " + this.ipAddress);
		if (this.ipAddress.getHostAddress().equals(this.detectionAgentIP))
		   	outBuf.println("WRITE " + DETECTION_AGENT_ELEMENT + "." + handlerName + " " + handlerText);
		else outBuf.println("WRITE " + ODIN_AGENT_ELEMENT + "." + handlerName + " " + handlerText);

		//outBuf.println("WRITE " + ODIN_AGENT_ELEMENT + "." + handlerName + " " + handlerText);
		//log.info("[invokeWriteHandler] End " + handlerName);
	}


	@Override
	public void sendProbeResponse(MACAddress clientHwAddr, MACAddress bssid, Set<String> ssidList) {
		StringBuilder sb = new StringBuilder();
		sb.append(clientHwAddr);
		sb.append(" ");
		sb.append(bssid);

		for (String ssid: ssidList) {
			sb.append(" ");
			sb.append(ssid);
		}

		invokeWriteHandler(WRITE_HANDLER_SEND_PROBE_RESPONSE, sb.toString());
	}
	
	@Override
	public void setChannel(int channel) {
		//Wi5- TODO: We should announce to the APs the change of the channel. This need futher discusssion
		if(channel != this.channel) 
			this.channel = channel;
		String chan = Integer.toString(channel);
		invokeWriteHandler(WRITE_HANDLER_CHANNEL, chan);
	}
	
	@Override
	public int getChannel() {
		int chan = 0;
		String handler = invokeReadHandler(READ_HANDLER_CHANNEL);
		chan = Integer.parseInt(handler.trim());
		if(chan != this.channel)
			this.channel = chan;
		return this.channel;
	}
	
	@Override
	public void sendChannelSwitch(MACAddress clientHwAddr, MACAddress bssid, List<String> ssidList, int channel) {
		StringBuilder sb = new StringBuilder();
		sb.append(clientHwAddr);
		sb.append(" ");
		sb.append(bssid);
		sb.append(" ");
		sb.append(channel);
		for (String ssid: ssidList) {
			sb.append(" ");
			sb.append(ssid);
		}
		invokeWriteHandler(WRITE_HANDLER_CHANNEL_SWITCH_ANNOUNCEMENT, sb.toString());
	}
	 
	public int convertFrequencyToChannel(int freq) {
	    if (freq >= 2412 && freq <= 2484) {
	        int chan = (freq - 2412) / 5 + 1;
	        return chan;
	    } else if (freq >= 5170 && freq <= 5825) {
	        int chan = (freq - 5170) / 5 + 34;
	        return chan;
	    } else {
	        return -1;
	    }
	}
	
	public int convertChannelToFrequency(int chan) {
	    if (chan >= 1 && chan <= 14) {
	        int freq = 5 * (chan - 1) + 2412;
	        return freq;
	    } else if (chan >= 34 && chan <= 165) {
	        int freq = 5 * (chan - 34) + 5170;
	        return freq;
	    } else {
	        return -1;
	    }
	}


	@Override
	public int scanClient(MACAddress clientHwAddr, int channel, int time) {
		StringBuilder sb = new StringBuilder();
		sb.append(clientHwAddr);
		sb.append(" ");
		sb.append(channel);
		log.debug("Sending WRITE_HANDLER_SCAN_CLIENT " + sb.toString());
		invokeWriteHandler(WRITE_HANDLER_SCAN_CLIENT, sb.toString());
		try {
			Thread.sleep(time);
		} catch (InterruptedException e){
        		e.printStackTrace();
		}
		log.debug("Sending READ_HANDLER_SCAN_CLIENT");
		String handler = invokeReadHandler(READ_HANDLER_SCAN_CLIENT);
		lastScan = Integer.parseInt(handler.trim());
		log.debug("READ_HANDLER_SCAN_CLIENT " + lastScan);
		return lastScan;
	} 


	/**
	 * Request scanned stations statistics from the agent
	 * @param agentAddr InetAddress of the agent
	 * @param #channel to scan
	 * @param time interval to scan
	 * @param ssid to scan (always is *)
	 * @ If request is accepted return 1, otherwise, return 0
	 */
	@Override
	public int requestScannedStationsStats (int channel, String ssid) { // Log disabled
		//log.info("Sending READ_HANDLER_SCANNING_FLAGS");
		String flags = invokeReadHandler(READ_HANDLER_SCANING_FLAGS);
		//log.info("Received flags: " + flags);
		String row[] = flags.split(" ");
		int client_scanning_flag = Integer.parseInt(row[0].trim());
		int AP_scanning_flag = Integer.parseInt(row[1].trim());
		int measurement_beacon_flag = Integer.parseInt(row[2].trim());
		//log.info("READ_HANDLER_SCANING_FLAGS ---- " + " client_scanning_flag:" + client_scanning_flag + " AP_scanning_flag:" + AP_scanning_flag + " measurement_beacon_flag:" + measurement_beacon_flag);
    	if (client_scanning_flag == 1 || AP_scanning_flag == 1 || measurement_beacon_flag == 1) 
				return (0);

		StringBuilder sb = new StringBuilder();
		sb.append(ssid);
		sb.append(" ");
		sb.append(channel);
		//log.info("Sending WRITE_HANDLER_SCAN_APS " + sb.toString());
		invokeWriteHandler(WRITE_HANDLER_SCAN_APS, sb.toString());
		return (1);
	}


	/**
	 * Retreive scanned stations statistics from the agent
	 * @param agentAddr InetAddress of the agent
	 * @return Key-Value entries of each recorded statistic for each station 
	 */
	@Override
	public Map<MACAddress, Map<String, String>> getScannedStationsStats (String ssid) {

		String stats = invokeReadHandler(READ_HANDLER_SCAN_APS);

		Map<MACAddress, Map<String, String>> ret = new HashMap<MACAddress, Map<String, String>>();

		int num_properties;
		if (ssid == "*")
			 num_properties = RX_STAT_NUM_PROPERTIES;
		else num_properties = MTX_DISTANCE_RX_STAT_NUM_PROPERTIES;

		/*
		 * We basically get rows like this MAC_ADDR1 prop1:<value> prop2:<value>
		 * MAC_ADDR2 prop1:<value> prop2:<value>
		 */
		String arr[] = stats.split("\n");
		for (String elem : arr) {
			String row[] = elem.split(" ");

			if (row.length != num_properties + 1) {
				continue;
			}

			MACAddress eth = MACAddress.valueOf(row[0].toLowerCase());

			Map<String, String> innerMap = new HashMap<String, String>();

			for (int i = 1; i < num_properties + 1; i += 1) {
				innerMap.put(row[i].split(":")[0], row[i].split(":")[1]);
			}

			ret.put(eth, Collections.unmodifiableMap(innerMap));
		}

		return Collections.unmodifiableMap(ret);
	}


	/**
	 * Request the agent to start sending measurement beacons
	 * @param agentAddr InetAddress of the agent
	 * @param #channel to send measurement beacon
	 * @param time interval to send measurement beacon
	 * @param ssid to scan (e.g odin_init)
	 * @ If request is accepted return 1, otherwise, return 0
	 */
	@Override
	public int requestSendMesurementBeacon (int channel, String ssid) {
		log.info("Sending READ_HANDLER_SCANING_FLAGS");
		String flags = invokeReadHandler(READ_HANDLER_SCANING_FLAGS);
		log.info("Received flags: " + flags);
		String row[] = flags.split(" ");
		int client_scanning_flag = Integer.parseInt(row[0].trim());
		int AP_scanning_flag = Integer.parseInt(row[1].trim());
		int measurement_beacon_flag = Integer.parseInt(row[2].trim());
		log.info("READ_HANDLER_SCANING_FLAGS ---- " + " client_scanning_flag:" + client_scanning_flag + " AP_scanning_flag:" + AP_scanning_flag + " measurement_beacon_flag:" + measurement_beacon_flag);
    	if (client_scanning_flag == 1 || AP_scanning_flag == 1 || measurement_beacon_flag == 1) 
				return (0);
		
		StringBuilder sb = new StringBuilder();
		sb.append(ssid);
		sb.append(" ");
		sb.append(channel);
		log.info("Sending WRITE_HANDLER_SEND_MEASUREMENT_BEACON " + sb.toString());
		invokeWriteHandler(WRITE_HANDLER_SEND_MEASUREMENT_BEACON, sb.toString());
		return (1);
	}

	

	/**
	 * Request the agent to stop sending measurement beacons
	 * 
	 * @param agentAddr InetAddress of the agent
	 * 
	 */
	@Override
	public int stopSendMesurementBeacon () {
		int client_scanning_flag = 0;
		int AP_scanning_flag = 0;
		int measurement_beacon_flag = 0;
		StringBuilder sb = new StringBuilder();
		sb.append(client_scanning_flag);
		sb.append(" ");
		sb.append(AP_scanning_flag);
		sb.append(" ");
		sb.append(measurement_beacon_flag);
		log.info("Sending WRITE_HANDLER_SCANING_FLAGS " + sb.toString());
		invokeWriteHandler(WRITE_HANDLER_SCANING_FLAGS, sb.toString());
		return (1);
	}
	
	
	/**
	 * Get TxPower from the agent
	 * 
	 * @param agentAddr InetAddress of the agent
	 * 
	 */
	@Override
	public int getTxPower() {
		int txpower = 0;
		String handler = invokeReadHandler(READ_HANDLER_TXPOWER);
		txpower = Integer.parseInt(handler.trim());
		if(txpower != this.txpower)
			this.txpower = txpower;
		return this.txpower;
	}

	/**
	 * Returns the Detector IP address added in poolfile
	 * 
	 * @return Detector InetAddress
	 */
	//@Override
	public String setDetectorIpAddress(){
		String detectorIp = OdinMaster.getDetectorIpAddress();
		return detectorIp;	
	}
	
	/**
	 * Retrieve scanned wi5 stations rssi from the agent
	 * @param agentAddr InetAddress of the agent
	 * @return Key-Value entries of each recorded rssi for each wi5 station 
	 */
	public String getScannedStaRssi () { // Test with String in App trying to get lower response time
    
		String stats = invokeReadHandler(READ_HANDLER_STA_RSSI);

		return stats;
	}
}
