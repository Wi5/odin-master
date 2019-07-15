package net.floodlightcontroller.odin.master;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import javax.sound.midi.MidiDevice.Info;

import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.DHCP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPacket;
import net.floodlightcontroller.restserver.IRestApiService;
import net.floodlightcontroller.storage.IStorageSourceService;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.util.MACAddress;


/**
 * OdinMaster implementation. Exposes interfaces to OdinApplications,
 * and keeps track of agents and clients in the system.
 *
 * @author Lalith Suresh <suresh.lalith@gmail.com>
 *
 */
public class OdinMaster implements IFloodlightModule, IOFSwitchListener, IOdinMasterToApplicationInterface, IOFMessageListener, IFloodlightService {
	protected static Logger log = LoggerFactory.getLogger(OdinMaster.class);
	protected IRestApiService restApi;

	private IStorageSourceService storageSourceService;
	private IFloodlightProviderService floodlightProvider;
	private ScheduledExecutorService executor;

	private final AgentManager agentManager;
	private final ClientManager clientManager;
	private final LvapManager lvapManager;
	private final PoolManager poolManager;

	private long subscriptionId = 0;
	private String subscriptionList = "";
	private long flowdetectionId = 0;
	private String flowdetectionList = "";
	private int idleLvapTimeout = 60; // Seconds

	private final ConcurrentMap<Long, SubscriptionCallbackTuple> subscriptions = new ConcurrentHashMap<Long, SubscriptionCallbackTuple>();

	private final ConcurrentMap<Long, FlowDetectionCallbackTuple> flowsdetection = new ConcurrentHashMap<Long, FlowDetectionCallbackTuple>();

	private static String detector_ip_address = "0.0.0.0"; // Detector Ip Address not assigned
	
  private static String vip_ap_ip_address = "0.0.0.0"; // Detector Ip Address not assigned
	
	private static MobilityParams mobility_params; // MobilityManager parameters
	
	private static ScannParams matrix_params; // ShowMatrixOfDistancedBs parameters
	
	private static ScannParams interference_params; // ShowScannedStationsStatistics parameters
	
	private static ChannelAssignmentParams channel_params; // ChannelAssignment parameters
	
	private static SmartApSelectionParams smartap_params; // SmartApSelection parameters

	private static SmartApSelectionTextParams smartap_text_params; // SmartApSelectionText parameters

	// some defaults
	static private final String DEFAULT_POOL_FILE = "poolfile";
	static private final String DEFAULT_CLIENT_LIST_FILE = "odin_client_list";
	static private final int DEFAULT_PORT = 2819;
 
  	public List<OdinApplication> applicationList;

	public OdinMaster(){
		clientManager = new ClientManager();
		lvapManager = new LvapManager();
		poolManager = new PoolManager();
		agentManager = new AgentManager(clientManager, poolManager);
	}

	public OdinMaster(AgentManager agentManager, ClientManager clientManager, LvapManager lvapManager, PoolManager poolManager){
		this.agentManager = agentManager;
		this.clientManager = clientManager;
		this.lvapManager = lvapManager;
		this.poolManager = poolManager;
	}


	//********* Odin Agent->Master protocol handlers *********//

	/**
	 * Handle a ping from an agent
	 *
	 * @param InetAddress of the agent
	 */
	synchronized void receivePing (final InetAddress odinAgentAddr) {
		
		if (agentManager.receivePing(odinAgentAddr)&&(!odinAgentAddr.getHostAddress().equals(OdinMaster.detector_ip_address))) { // Detector does not need to be checked
			log.info(odinAgentAddr.getHostAddress() + " is a new agent");
			// if the above leads to a new agent being
			// tracked, push the current subscription list
			// to it.
			IOdinAgent agent = agentManager.getAgent(odinAgentAddr);
			pushSubscriptionListToAgent(agent);
			
			// Reclaim idle lvaps and also attach flows to lvaps
			for (OdinClient client: agent.getLvapsLocal()) {
				executor.schedule(new IdleLvapReclaimTask(client), idleLvapTimeout, TimeUnit.SECONDS);

				// Assign flow tables
				if (!client.getIpAddress().getHostAddress().equals("0.0.0.0")) {

					// Obtain reference to client entity from clientManager, because agent.getLvapsLocal()
					// returns a separate copy of the client objects.
					OdinClient trackedClient = clientManager.getClients().get(client.getMacAddress());
					Lvap lvap = trackedClient.getLvap();
					assert (lvap != null);
					lvap.setOFMessageList(lvapManager.getDefaultOFModList(client.getIpAddress()));

					// Push flow messages associated with the client
        			try {
        				lvap.getAgent().getSwitch().write(lvap.getOFMessageList(), null);
        			} catch (IOException e) {
        				log.error("Failed to update switch's flow tables " + lvap.getAgent().getSwitch());
        			}
				}
			}
		}
		else {
            if(!odinAgentAddr.getHostAddress().equals(OdinMaster.detector_ip_address)){
                updateAgentLastHeard (odinAgentAddr);
            }
		}
	}

	synchronized void receiveDeauth (final InetAddress odinAgentAddr, final MACAddress clientHwAddress) {

		if (clientHwAddress == null || odinAgentAddr == null)
			return;

		IOdinAgent agent = agentManager.getAgent(odinAgentAddr);
		OdinClient oc = clientManager.getClient(clientHwAddress);

		if(agent == null)
			return;

		log.info("Clearing Lvap " + clientHwAddress +
		" from agent:" + agent.getIpAddress() + " due to deauthentication/inactivity");
		poolManager.removeClientPoolMapping(oc);
		agent.removeClientLvap(oc);
		clientManager.removeClient(clientHwAddress);

	}

	/* This method stops the timer that clears the lvap if an IP is not received for the client */
	synchronized void receiveAssoc (final InetAddress odinAgentAddr, final MACAddress clientHwAddress) {

		if (clientHwAddress == null || odinAgentAddr == null)
			return;

		IOdinAgent agent = agentManager.getAgent(odinAgentAddr);

		if(agent == null)
			return;

		log.info("Client " + clientHwAddress + " completed the association");

		OdinClient oc = clientManager.getClient(clientHwAddress);
		oc.getLvap().setAssocState(true); //associated;

		//poolManager.removeClientPoolMapping(oc);
		//agent.removeClientLvap(oc);
		//clientManager.removeClient(clientHwAddress);

	}

	/**
	 * Handle a probe message from an agent, triggered
	 * by a particular client.
	 *
	 * @param odinAgentAddr InetAddress of agent
	 * @param clientHwAddress MAC address of client that performed probe scan
	 */
	synchronized void receiveProbe (final InetAddress odinAgentAddr, final MACAddress clientHwAddress, String ssid) {

		if (odinAgentAddr == null
	    	|| clientHwAddress == null
	    	|| clientHwAddress.isBroadcast()
	    	|| clientHwAddress.isMulticast()
	    	|| agentManager.isTracked(odinAgentAddr) == false
	    	|| poolManager.getNumNetworks() == 0) {
			return;
		}

		updateAgentLastHeard(odinAgentAddr);

		/*
		 * If clients perform an active scan, generate
		 * probe responses without spawning lvaps
		 */
		if (ssid.equals("")) {   // FIXMeE:  Are you sure this is right, the client can delete the network.
			// we just send probe responses
			IOdinAgent agent = agentManager.getAgent(odinAgentAddr);
			MACAddress bssid = poolManager.generateBssidForClient(clientHwAddress);

			// FIXME: Sub-optimal. We'll end up generating redundant probe requests
			Set<String> ssidSet = new TreeSet<String> ();
			for (String pool: poolManager.getPoolsForAgent(odinAgentAddr)) {

				if (pool.equals(PoolManager.GLOBAL_POOL)) //???????
					continue;

				ssidSet.addAll(poolManager.getSsidListForPool(pool));
			}

			executor.execute(new OdinAgentSendProbeResponseRunnable(agent, clientHwAddress, bssid, ssidSet));

			return;
		}

		/*
		 * Client is scanning for a particular SSID. Verify
		 * which pool is hosting the SSID, and assign
		 * an LVAP into that pool
		 */
		for (String pool: poolManager.getPoolsForAgent(odinAgentAddr)) {
			if (poolManager.getSsidListForPool(pool).contains(ssid)) {
				OdinClient oc = clientManager.getClient(clientHwAddress);

		    	// Hearing from this client for the first time
		    	if (oc == null) {
					List<String> ssidList = new ArrayList<String> ();
					ssidList.addAll(poolManager.getSsidListForPool(pool));

					Lvap lvap = new Lvap (poolManager.generateBssidForClient(clientHwAddress), ssidList); 
					//FIXME: WHy not before also? -- because only when you connect to the network u store it.

					try {
						oc = new OdinClient(clientHwAddress, InetAddress.getByName("0.0.0.0"), lvap);
					} catch (UnknownHostException e) {
						e.printStackTrace();
					}
		    		clientManager.addClient(oc);
		    	}

		    	Lvap lvap = oc.getLvap();
		    	assert (lvap != null);

				if (lvap.getAgent() == null) {
					// client is connecting for the
					// first time, had explicitly
					// disconnected, or knocked
					// out at as a result of an agent
					// failure.pr first time connections
					handoffClientToApInternal(PoolManager.GLOBAL_POOL, clientHwAddress, odinAgentAddr);
				}

				poolManager.mapClientToPool(oc, pool);

				return;
			}
		}
	}

	/**
	 * Handle an event publication from an agent
	 *
	 * @param clientHwAddress client which triggered the event
	 * @param odinAgentAddr agent at which the event was triggered
	 * @param subscriptionIds list of subscription Ids that the event matches
	 */
	synchronized void receivePublish (final MACAddress clientHwAddress, final InetAddress odinAgentAddr, final Map<Long, Long> subscriptionIds) {

		// The check for null clientHwAddress might go away
		// in the future if we end up having events
		// that are not related to clients at all.
		if (clientHwAddress == null || odinAgentAddr == null || subscriptionIds == null)
			return;

		IOdinAgent oa = agentManager.getAgent(odinAgentAddr);

		// This should never happen!
		if (oa == null)
			return;

		// Update last-heard for failure detection
		oa.setLastHeard(System.currentTimeMillis());

		for (Entry<Long, Long> entry: subscriptionIds.entrySet()) {
			SubscriptionCallbackTuple tup = subscriptions.get(entry.getKey());

			/* This might occur as a race condition when the master
			 * has cleared all subscriptions, but hasn't notified
			 * the agent about it yet.
			 */
			if (tup == null)
				continue;


			NotificationCallbackContext cntx = new NotificationCallbackContext(clientHwAddress, oa, entry.getValue(),0,0);

			tup.cb.exec(tup.oes, cntx);
		}
	}
	

	/**
	 * Handle an event flow detection from an agent
	 *
     * @param odinAgentAddr InetAddress of the agent at which the event was triggered
	 * @param detectedFlowIds  list of detected flow Ids that the event matches. String contains the detected flow: "IPSrcAddress IPDstAddress Protocol SrcPort DstPort"
	 */
	synchronized void receiveDetectedFlow (final InetAddress odinAgentAddr, final Map<Long, String> detectedFlowIds) {
	
		if (odinAgentAddr == null || detectedFlowIds == null)
			return;
	
		//IOdinAgent oa = agentManager.getAgent(odinAgentAddr);
		// This should never happen!
		//if (oa == null)
			//return;
		// Update last-heard for failure detection
		//oa.setLastHeard(System.currentTimeMillis());

		//FIXME: Always detect all flows --> flowsdetection is equal to (IP source address  = *, IP destination address = *, Protocol = 0, Source Port = 0 and Destination Port = 0)
		// list of detected flow Ids have a only ID (always is 1)
		for (Entry<Long, String> entry: detectedFlowIds.entrySet()) {
			FlowDetectionCallbackTuple tup = flowsdetection.get(entry.getKey());

			if (tup == null)
				continue;

			final String[] fields = entry.getValue().split(" ");
      	    final String IPSrcAddress = fields[0];
			final String IPDstAddress = fields[1];
			final int protocol = Integer.parseInt(fields[2]);
			final int SrcPort = Integer.parseInt(fields[3]);
			final int DstPort = Integer.parseInt(fields[4]);

			//log.info("We receive a detected flow "+ IPSrcAddress + " " + IPDstAddress + " " + protocol + " " + SrcPort + " " + DstPort + " " + "registered as Id: " + entry.getKey() + "  from: " + odinAgentAddr.getHostAddress());
			
			FlowDetectionCallbackContext cntx = new FlowDetectionCallbackContext(odinAgentAddr, IPSrcAddress, IPDstAddress, protocol, SrcPort, DstPort );
			//FlowDetectionCallbackContext cntx = new FlowDetectionCallbackContext(oa, IPSrcAddress, IPDstAddress, protocol, SrcPort, DstPort );

			tup.cb.exec(tup.oefd, cntx);
		}
	}


	/**
	 * VAP-Handoff a client to a new AP. This operation is idempotent.
	 *
	 * @param newApIpAddr IPv4 address of new access point
	 * @param hwAddrSta Ethernet address of STA to be handed off
	 */
	private void handoffClientToApInternal (String pool, final MACAddress clientHwAddr, final InetAddress newApIpAddr){

		// As an optimisation, we probably need to get the accessing done first,
		// prime both nodes, and complete a handoff.

		if (pool == null || clientHwAddr == null || newApIpAddr == null) {
			log.error("null argument in handoffClientToAp(): pool: " + pool + "clientHwAddr: " + clientHwAddr + " newApIpAddr: " + newApIpAddr);
			return;
		}

		synchronized (this) {

			IOdinAgent newAgent = agentManager.getAgent(newApIpAddr);

			// If new agent doesn't exist, ignore request
			if (newAgent == null) {
				log.error("Handoff request ignored: OdinAgent " + newApIpAddr + " doesn't exist");
				return;
			}

			OdinClient client = clientManager.getClient(clientHwAddr);

			// Ignore request if we don't know the client
			if (client == null) {
				log.error("Handoff request ignored: OdinClient " + clientHwAddr + " doesn't exist");
				return;
			}

			Lvap lvap = client.getLvap();

			assert (lvap != null);

			/* If the client is connecting for the first time, then it
			 * doesn't have a VAP associated with it already
			 */
			if (lvap.getAgent() == null) {
				log.info ("Client: " + clientHwAddr + " connecting for first time. Assigning to: " + newAgent.getIpAddress());

				// Push flow messages associated with the client
				try {
					newAgent.getSwitch().write(lvap.getOFMessageList(), null);
				} catch (IOException e) {
					log.error("Failed to update switch's flow tables " + newAgent.getSwitch());
				}

				newAgent.addClientLvap(client);
				lvap.setAgent(newAgent);
				executor.schedule(new IdleLvapReclaimTask (client), idleLvapTimeout, TimeUnit.SECONDS);
				return;
			}

			/* If the client is already associated with AP-newIpAddr, we ignore
			 * the request.
			 */
			InetAddress currentApIpAddress = lvap.getAgent().getIpAddress();
			if (currentApIpAddress.getHostAddress().equals(newApIpAddr.getHostAddress())) {
				log.info ("Client " + clientHwAddr + " is already associated with AP " + newApIpAddr);
				return;
			}

			/* Verify permissions.
			 *
			 * - newAP and oldAP should both fall within the same pool.
			 * - client should be within the same pool as the two APs.
			 * - invoking application should be operating on the same pools
			 *
			 * By design, this prevents handoffs within the scope of the
			 * GLOBAL_POOL since that would violate a lot of invariants
			 * in the rest of the system.
			 */

			String clientPool = poolManager.getPoolForClient(client);
			
			if (clientPool == null || !clientPool.equals(pool)) {
				log.error ("Cannot handoff client '" + client.getMacAddress() + "' from " + clientPool + " domain when in domain: '" + pool + "'");
			}

			if (! (poolManager.getPoolsForAgent(newApIpAddr).contains(pool)
					&& poolManager.getPoolsForAgent(currentApIpAddress).contains(pool)) ){
				log.info ("Agents " + newApIpAddr + " and " + currentApIpAddress + " are not in the same pool: " + pool);
				return;
			}

			// Wi5 Add: Are the APs in the same channel? If not, start CSA procedure.
			if ((agentManager.getAgent(currentApIpAddress)).getChannel() != (agentManager.getAgent(newApIpAddr)).getChannel()) {
				//Send CSA messages and wait.
				sendChannelSwitchToClient(clientPool,currentApIpAddress, clientHwAddr, client.getLvap().getSsids(),(agentManager.getAgent(newApIpAddr)).getChannel());
				//void sendChannelSwitchToClient (String pool, InetAddress agentAddr, MACAddress clientHwAddr, List<String> lvapSsids, int channel);
				
			}
			
			// Push flow messages associated with the client
			try {
				newAgent.getSwitch().write(lvap.getOFMessageList(), null);
			} catch (IOException e) {
				log.error("Failed to update switch's flow tables " + newAgent.getSwitch());
			}

			/* Client is with another AP. We remove the VAP from
			 * the current AP of the client, and spawn it on the new one.
			 * We split the add and remove VAP operations across two threads
			 * to make it faster. Note that there is a temporary inconsistent
			 * state between setting the agent for the client and it actually
			 * being reflected in the network
			 */
			lvap.setAgent(newAgent);
			executor.execute(new OdinAgentLvapAddRunnable(newAgent, client));
			executor.execute(new OdinAgentLvapRemoveRunnable(agentManager.getAgent(currentApIpAddress), client));
		}
	}
	
	/**
	 * Return Detector Ip Address
	 *
	 * @return String Detector Ip Address
	 */
	//@Override
	public static String getDetectorIpAddress (){
		return OdinMaster.detector_ip_address;
	}
	
	/**
	 * Return Vip AP Ip Address
	 *
	 * @return String VIP AP Ip Address
	 */
	@Override
	public String getVipAPIpAddress (){
		return OdinMaster.vip_ap_ip_address;
	}

	//********* Odin methods to be used by applications (from IOdinMasterToApplicationInterface) **********//

	/**
	 * VAP-Handoff a client to a new AP. This operation is idempotent.
	 *
	 * @param newApIpAddr IPv4 address of new access point
	 * @param hwAddrSta Ethernet address of STA to be handed off
	 */
	@Override
	public void handoffClientToAp (String pool, final MACAddress clientHwAddr, final InetAddress newApIpAddr){
		handoffClientToApInternal(pool, clientHwAddr, newApIpAddr);
	}


	/**
	 * Get the list of clients currently registered with Odin
	 *
	 * @return a map of OdinClient objects keyed by HW Addresses
	 */
	@Override
	public Set<OdinClient> getClients (String pool) {
		return poolManager.getClientsFromPool(pool);
	}


	/**
	 * Get the OdinClient type from the client's MACAddress
	 *
	 * @param pool that the invoking application corresponds to
	 * @param clientHwAddress MACAddress of the client
	 * @return a OdinClient instance corresponding to clientHwAddress
	 */
	@Override
	public OdinClient getClientFromHwAddress (String pool, MACAddress clientHwAddress) {
		OdinClient client = clientManager.getClient(clientHwAddress);
		return (client != null && poolManager.getPoolForClient(client).equals(pool)) ? client : null;
	}

	
	/**
	 * Retreive LastHeard from the agent
	 * 
	 * @param pool that the invoking application corresponds to
	 * @param agentAddr InetAddress of the agent
	 * 
	 * @return timestamp of the last ping heard from the agent
	 */
	@Override
	public long getLastHeardFromAgent (String pool, InetAddress agentAddr) {
		return agentManager.getAgent(agentAddr).getLastHeard();
	}

	
	/**
	 * Retreive TxStats from the agent
	 *
	 * @param pool that the invoking application corresponds to
	 * @param agentAddr InetAddress of the agent
	 *
	 * @return Key-Value entries of each recorded statistic for each client
	 */
	@Override
	public Map<MACAddress, Map<String, String>> getTxStatsFromAgent (String pool, InetAddress agentAddr) {
		return agentManager.getAgent(agentAddr).getTxStats();
	}

	
	/**
	 * Retreive RxStats from the agent
	 *
	 * @param pool that the invoking application corresponds to
	 * @param agentAddr InetAddress of the agent
	 *
	 * @return Key-Value entries of each recorded statistic for each client
	 */
	public Map<MACAddress, Map<String, String>> getRxStatsFromAgent (String pool, InetAddress agentAddr) {
		return agentManager.getAgent(agentAddr).getRxStats();
	}


	/**
	 * Request scanned stations statistics from the agent
	 * 
	 * @param agentAddr InetAddress of the agent
	 * 
	 * @param #channel to scan
	 * 
	 * @param time interval to scan
	 * 
	 * @param ssid to scan (always is *)
	 * 
	 * @ If request is accepted return 1, otherwise, return 0
	 */
	@Override
	public int requestScannedStationsStatsFromAgent (String pool, InetAddress agentAddr, int channel, String ssid) {
		return agentManager.getAgent(agentAddr).requestScannedStationsStats(channel, ssid);
	}                                           


	/**
	 * Retreive scanned stations statistics from the agent
	 * 
	 * @param agentAddr InetAddress of the agent
	 * 
	 * @return Key-Value entries of each recorded statistic for each station 
	 */
	@Override
	public Map<MACAddress, Map<String, String>> getScannedStationsStatsFromAgent (String pool, InetAddress agentAddr, String ssid) {
		return agentManager.getAgent(agentAddr).getScannedStationsStats(ssid);
	}


	/**
	
	 * Request scanned stations statistics from the agent
	 * 
	 * @param agentAddr InetAddress of the agent
	 * 
	 * @param #channel to send mesurement beacon
	 * 
	 * @param time interval to send mesurement beacon
	 * 
	 * @param ssid to scan (e.g odin_init)
	 * 
	 * @ If request is accepted return 1, otherwise, return 0
	 */
	@Override
	public int requestSendMesurementBeaconFromAgent (String pool, InetAddress agentAddr, int channel, String ssid) {
		return agentManager.getAgent(agentAddr).requestSendMesurementBeacon(channel, ssid);
	}


	/**
	 * Stop sending mesurement beacon from the agent
	 * 
	 * @param agentAddr InetAddress of the agent
	 * 
	 */
	@Override
	public int stopSendMesurementBeaconFromAgent (String pool, InetAddress agentAddr) {
		return agentManager.getAgent(agentAddr).stopSendMesurementBeacon();
	}




	/**
	 * Get a list of Odin agents from the agent tracker
	 * @return a map of OdinAgent objects keyed by Ipv4 addresses
	 */
	@Override
	public Set<InetAddress> getAgentAddrs (String pool){
		return poolManager.getAgentAddrsForPool(pool);
	}


	/**
	 * Add a subscription for a particular event defined by oes. cb
	 * defines the application specified callback to be invoked during
	 * notification. If the application plans to delete the subscription,
	 * later, the onus is upon it to keep track of the subscription
	 * id for removal later.
	 *
	 * @param oes the susbcription
	 * @param cb the callback
	 */
	@Override
	public synchronized long registerSubscription (String pool, final OdinEventSubscription oes, final NotificationCallback cb) {
		// FIXME: Need to calculate subscriptions per pool
		assert (oes != null);
		assert (cb != null);
		SubscriptionCallbackTuple tup = new SubscriptionCallbackTuple();
		tup.oes = oes;
		tup.cb = cb;
		subscriptionId++;
		subscriptions.put(subscriptionId, tup);

		/**
		 * Update the subscription list, and push to all agents
		 * TODO: This is a common subsription string being
		 * sent to all agents. Replace this with per-agent
		 * subscriptions.
		 */
		subscriptionList = "";
		int count = 0;
		for (Entry<Long, SubscriptionCallbackTuple> entry: subscriptions.entrySet()) {
			count++;
			final String addr = entry.getValue().oes.getClient();
			subscriptionList = subscriptionList +
								entry.getKey() + " " +
								(addr.equals("*") ? MACAddress.valueOf("00:00:00:00:00:00") : addr)  + " " +
								entry.getValue().oes.getStatistic() + " " +
								entry.getValue().oes.getRelation().ordinal() + " " +
								entry.getValue().oes.getValue() + " ";
		}

		subscriptionList = String.valueOf(count) + " " + subscriptionList;

		/**
		 * Should probably have threads to do this
		 */
		for (InetAddress agentAddr : poolManager.getAgentAddrsForPool(pool)) {
			pushSubscriptionListToAgent(agentManager.getAgent(agentAddr));
		}

		return subscriptionId;
	}


	/**
	 * Remove a subscription from the list
	 *
	 * @param id subscription id to remove
	 * @return
	 */
	@Override
	public synchronized void unregisterSubscription (String pool, final long id) {
		// FIXME: Need to calculate subscriptions per pool
		subscriptions.remove(id);

		subscriptionList = "";
		int count = 0;
		for (Entry<Long, SubscriptionCallbackTuple> entry: subscriptions.entrySet()) {
			count++;
			final String addr = entry.getValue().oes.getClient();
			subscriptionList = subscriptionList +
								entry.getKey() + " " +
								(addr.equals("*") ? MACAddress.valueOf("00:00:00:00:00:00") : addr)  + " " +
								entry.getValue().oes.getStatistic() + " " +
								entry.getValue().oes.getRelation().ordinal() + " " +
								entry.getValue().oes.getValue() + " ";
		}

		subscriptionList = String.valueOf(count) + " " + subscriptionList;

		/**
		 * Should probably have threads to do this
		 */
		for (InetAddress agentAddr : poolManager.getAgentAddrsForPool(pool)) {
			pushSubscriptionListToAgent(agentManager.getAgent(agentAddr));
		}
	}


	/**
	 * Add a flow detection for a particular event defined by oefd. cb
	 * defines the application specified callback to be invoked during
	 * notification. If the application plans to delete the flow detection,
	 * later, the onus is upon it to keep track of the flow detection
	 * id for removal later.
	 *
	 * @param oefd the flow detection
	 * @param cb the callback
	 */
	@Override
	public synchronized long registerFlowDetection (String pool, final OdinEventFlowDetection oefd, final FlowDetectionCallback cb) {
		// FIXME: Need to calculate subscriptions per pool
		
		assert (oefd != null);
		assert (cb != null);
		
		FlowDetectionCallbackTuple tup = new FlowDetectionCallbackTuple();
		tup.oefd = oefd;
		tup.cb = cb;
		flowdetectionId++;
		flowsdetection.put(flowdetectionId, tup);

		/**
		 * Update the flowsdetection list, and push to all agents
		 * TODO: This is a common flow2detect string being
		 * sent to all agents. Replace this with per-agent
		 * flow2detect.
		 */
		flowdetectionList = "";
		int count = 0;
		for (Entry<Long, FlowDetectionCallbackTuple> entry: flowsdetection.entrySet()) {
			count++;
			flowdetectionList = flowdetectionList +
								entry.getKey() + " " +
								entry.getValue().oefd.getIPSrcAddress() + " " +
								entry.getValue().oefd.getIPDstAddress() + " " +
								entry.getValue().oefd.getProtocol() + " " +
								entry.getValue().oefd.getSrcPort() + " " +
								entry.getValue().oefd.getDstPort() + " ";
		}

		flowdetectionList = String.valueOf(count) + " " + flowdetectionList;

		/**
		 * FIXME:  Only one registered request: detect all flows. And it is not sent to agents 
		 *
		 * Only in case of sending to the agents the registered flows to detect
		 * Should probably have threads to do this
		 *
		 *  for (InetAddress agentAddr : poolManager.getAgentAddrsForPool(pool)) {
		 *	    pushSubscriptionListToAgent(agentManager.getAgent(agentAddr));
			
		}*/

		return flowdetectionId;
	}


	/**
	 * Remove a flow detection from the list
	 *
	 * @param id flow detection id to remove
	 * @return
	 */
	@Override
	public synchronized void unregisterFlowDetection (String pool, final long id) {
		// FIXME: Need to calculate subscriptions per pool
		flowsdetection.remove(id);

		flowdetectionList = "";
		int count = 0;
		for (Entry<Long, FlowDetectionCallbackTuple> entry: flowsdetection.entrySet()) {
			count++;
			flowdetectionList = flowdetectionList +
								entry.getKey() + " " +
								entry.getValue().oefd.getIPSrcAddress() + " " +
								entry.getValue().oefd.getIPDstAddress() + " " +
								entry.getValue().oefd.getProtocol() + " " +
								entry.getValue().oefd.getSrcPort() + " " +
								entry.getValue().oefd.getDstPort() + " ";		
		}

		flowdetectionList = String.valueOf(count) + " " + flowdetectionList;

		/**
		 * FIXME:  Only one registered request: detect all flows. And it is not sent to agents 
		 *
		 * Only in case of sending to the agents the registered flows to detect
		 * Should probably have threads to do this
		 *
		 *  for (InetAddress agentAddr : poolManager.getAgentAddrsForPool(pool)) {
		 *	    pushSubscriptionListToAgent(agentManager.getAgent(agentAddr));
			
		}*/
		
	}

	
	/**
	 * Add an SSID to the Odin network.
	 *
	 * @param networkName
	 * @return true if the network could be added, false otherwise
	 */
	@Override
	public synchronized boolean addNetwork (String pool, String ssid) {
		if (poolManager.addNetworkForPool(pool, ssid)) {

			for(OdinClient oc: poolManager.getClientsFromPool(pool)) {
				Lvap lvap = oc.getLvap();
				assert (lvap != null);
				lvap.getSsids().add(ssid);

				IOdinAgent agent = lvap.getAgent();

				if (agent != null) {
					// FIXME: Ugly API
					agent.updateClientLvap(oc);
				}
			}

			return true;
		}

		return false;
	}
	


	/**
	 * Remove an SSID from the Odin network.
	 *
	 * @param networkName
	 * @return true if the network could be removed, false otherwise
	 */
	@Override
	public synchronized boolean removeNetwork (String pool, String ssid) {
		if (poolManager.removeNetworkFromPool(pool, ssid)){
			// need to update all existing lvaps in the network as well

			for (OdinClient oc: poolManager.getClientsFromPool(pool)) {

				Lvap lvap = oc.getLvap();
				assert (lvap != null);
				lvap.getSsids().remove(ssid);

				IOdinAgent agent = lvap.getAgent();

				if (agent != null) {
					// FIXME: Ugly API
					agent.updateClientLvap(oc);
				}				
			}

			return true;
		}

		return false;
	}

	/**
	 * Change the Wi-Fi channel of an specific agent (AP)
	 * 
	 * @param Pool
	 * @param Agent InetAddress
	 * @param Channel
	 */
	@Override
	public void setChannelToAgent (String pool, InetAddress agentAddr, int channel) {
		System.out.println("=================================CHANNEL CHANGE" + agentAddr + " - " + channel);
		IOdinAgent agent = agentManager.getAgent(agentAddr);
		if(agent!=null){
			agent.setChannel(channel);			
		}
	}
	
	/**
	 * Get channel from and specific agent (AP)
	 * 
	 * @param Pool
	 * @param Agent InetAddress
	 * @return Channel number
	 */
	@Override
	public int getChannelFromAgent (String pool, InetAddress agentAddr) {
		//log.info("Getting channel OdinMaster");
		return agentManager.getAgent(agentAddr).getChannel();
	}
	
	/**
	 * Channel Switch Announcement, to the clients of an specific agent (AP) -> Must it be private? 
	 * 
	 * @param Pool
	 * @param Agent InetAddress
	 * @param Client MAC
	 * @param SSID
	 * @param Channel 
	 */
	//@Override
	private void sendChannelSwitchToClient (String pool, InetAddress agentAddr, MACAddress clientHwAddr, List<String> lvapSsids, int channel) {		
		MACAddress bssid = poolManager.generateBssidForClient(clientHwAddr);
		agentManager.getAgent(agentAddr).sendChannelSwitch(clientHwAddr, bssid, lvapSsids, channel);
	}
	
	/**
	 * Scanning for a client in a specific agent (AP)
	 * 
	 * @param Pool
	 * @param Agent InetAddress
	 * @param Client MAC
	 * @param Channel
	 * @param Scanning time
	 * @return Signal power
	 */
	@Override
	public int scanClientFromAgent (String pool, InetAddress agentAddr, MACAddress clientHwAddr, int channel, int time){
		return agentManager.getAgent(agentAddr).scanClient(clientHwAddr, channel, time);
	}
	
	/**
	 * Get MobilityManager parameters
	 * 
	 * @return MobilityManager parameters
	 */
	@Override
	public MobilityParams getMobilityParams (){
		return OdinMaster.mobility_params;
		
	}
	/**
	 * Get Matrix parameters
	 * 
	 * @return Matrix parameters
	 */
	@Override
	public ScannParams getMatrixParams (){
		return OdinMaster.matrix_params;
		
	}
	/**
	 * Get Interference parameters
	 * 
	 * @return Interference parameters
	 */
	@Override
	public ScannParams getInterferenceParams (){
		return OdinMaster.interference_params;
		
	}
	
	/**
	 * Get ChannelAssignment parameters
	 * 
	 * @return ChannelAssignment parameters
	 */
	@Override
	public ChannelAssignmentParams getChannelAssignmentParams (){
		return OdinMaster.channel_params;
		
	}
	
	/**
	 * Get SmartApSelection parameters
	 * 
	 * @return SmartApSelection parameters
	 */
	@Override
	public SmartApSelectionParams getSmartApSelectionParams (){
		return OdinMaster.smartap_params;
		
	}
	
	/**
	 * Get SmartApSelectionText parameters
	 * 
	 * @return SmartApSelectionText parameters
	 */
	@Override
	public SmartApSelectionTextParams getSmartApSelectionTextParams (){
		return OdinMaster.smartap_text_params;
		
	}
	
	/**
	 * Get TxPower from and specific agent (AP)
	 * 
	 * @param Pool
	 * @param Agent InetAddress
	 * @return TxPower in dBm
	 */
	@Override
	public int getTxPowerFromAgent (String pool, InetAddress agentAddr) {
		//log.info("Getting TxPower OdinMaster");
		return agentManager.getAgent(agentAddr).getTxPower();
	}
	
	/**
	 * Retreive scanned wi5 stations rssi from the agent
	 * @param agentAddr InetAddress of the agent
	 * @return Key-Value entries of each recorded rssi for each wi5 station 
	 */
	@Override
	public String getScannedStaRssiFromAgent (String pool, InetAddress agentAddr) {
		return agentManager.getAgent(agentAddr).getScannedStaRssi();
	}
	
	/**
	 * Retreive associated wi5 stations in the agent
	 * @param agentAddr InetAddress of the agent
	 * @return Set of OdinClient associated in the agent
	 */
	@Override
	public Set<OdinClient> getClientsFromAgent (String pool, InetAddress agentAddr) {
		return agentManager.getAgent(agentAddr).getLvapsLocal();
	}

	//********* from IFloodlightModule **********//

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
	        new ArrayList<Class<? extends IFloodlightService>>();
	    l.add(IFloodlightProviderService.class);
        l.add(IRestApiService.class);
		return l;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		Map<Class<? extends IFloodlightService>,
        IFloodlightService> m =
        new HashMap<Class<? extends IFloodlightService>,
        IFloodlightService>();
        m.put(OdinMaster.class, this);
        return m;
	}

	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
   	storageSourceService = context.getServiceImpl(IStorageSourceService.class);
		restApi = context.getServiceImpl(IRestApiService.class);
		IThreadPoolService tp = context.getServiceImpl(IThreadPoolService.class);
		executor = tp.getScheduledExecutor();
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFSwitchListener(this);
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		restApi.addRestletRoutable(new OdinMasterWebRoutable());

		agentManager.setFloodlightProvider (floodlightProvider);
		
		// read config options
        Map<String, String> configOptions = context.getConfigParams(this);


        // List of trusted agents
        String agentAuthListFile = DEFAULT_POOL_FILE;
        String agentAuthListFileConfig = configOptions.get("poolFile");

        if (agentAuthListFileConfig != null) {
        	agentAuthListFile = agentAuthListFileConfig;
        }
        
        this.applicationList = new ArrayList<OdinApplication>();
       	try {
			BufferedReader br = new BufferedReader (new FileReader(agentAuthListFile));

			String strLine;

			/* Each line has the following format:
			 *
			 * IPAddr-of-agent  pool1 pool2 pool3 ...
			 */
			while ((strLine = br.readLine()) != null) {
				if (strLine.startsWith("#")) // comment
					continue;

				if (strLine.length() == 0) // blank line
					continue;

				// NAME
				String [] fields = strLine.split(" ");
				if (!fields[0].equals("NAME")) {
					log.error("Missing NAME field " + fields[0]);
					log.error("Offending line: " + strLine);
					System.exit(1);
				}

				if (fields.length != 2) {
					log.error("A NAME field should specify a single string as a pool name");
					log.error("Offending line: " + strLine);
					System.exit(1);
				}

				String poolName = fields[1];
				
				// NODES
				strLine = br.readLine();

				if (strLine == null) {
					log.error("Unexpected EOF after NAME field for pool: " + poolName);
					System.exit(1);
				}else if (strLine.startsWith("#")||(strLine.length() == 0)) // comment or blank line between params
					strLine = br.readLine();

				fields = strLine.split(" ");

				if (!fields[0].equals("NODES")){
					log.error("A NAME field should be followed by a NODES field");
					log.error("Offending line: " + strLine);
					System.exit(1);
				}

				if(fields.length == 1) {
					log.error("A pool must have at least one node defined for it");
					log.error("Offending line: " + strLine);
					System.exit(1);
				}

				for (int i = 1; i < fields.length; i++) {
					poolManager.addPoolForAgent(InetAddress.getByName(fields[i]), poolName);
				}

				// NETWORKS
				strLine = br.readLine();

				if (strLine == null) {
					log.error("Unexpected EOF after NODES field for pool: " + poolName);
					System.exit(1);
				}else if (strLine.startsWith("#")||(strLine.length() == 0)) // comment or blank line between params
					strLine = br.readLine();

				fields = strLine.split(" ");

				if (!fields[0].equals("NETWORKS")) {
					log.error("A NODES field should be followed by a NETWORKS field");
					log.error("Offending line: " + strLine);
					System.exit(1);
				}

				for (int i = 1; i < fields.length; i++) {
					poolManager.addNetworkForPool(poolName, fields[i]);
				}
				
				br.mark(1000);
				
				while ((strLine = br.readLine()) != null) {
					
					if (strLine.startsWith("#")||(strLine.length() == 0)){ 		// comment or blank line between params
						br.mark(1000);
						continue;
					}
					
					fields = strLine.split(" ");
					
					if (fields[0].equals("APPLICATION")){						// APPLICATION
						OdinApplication appInstance = (OdinApplication) Class.forName(fields[1]).newInstance();
						appInstance.setOdinInterface(this);
						appInstance.setPool(poolName);
						applicationList.add(appInstance);
						br.mark(1000);
						continue;
					}
					
					if (fields[0].equals("DETECTION")){							// DETECTION AGENT
						detector_ip_address = fields[1];
						log.info("Detector ip address " + detector_ip_address);
						br.mark(1000);
						continue;
					}
						
					if (fields[0].equals("MOBILITY")){							// MOBILITY MANAGER
						mobility_params = new MobilityParams(Integer.parseInt(fields[1]),Long.parseLong(fields[2]),Long.parseLong(fields[3]),Long.parseLong(fields[4]),Integer.parseInt(fields[5]),Integer.parseInt(fields[6]),Long.parseLong(fields[7]));
						log.info("Mobility Manager configured:");
						log.info("\t\tTime_to_start: " + mobility_params.time_to_start);
						log.info("\t\tIdle_client_threshold: " + mobility_params.idle_client_threshold);
						log.info("\t\tHysteresis_threshold: " + mobility_params.hysteresis_threshold);
						log.info("\t\tSignal_threshold: " + mobility_params.signal_threshold);
						log.info("\t\tScanning_time: " + mobility_params.scanning_time);
						log.info("\t\tNumber_of_triggers: " + mobility_params.number_of_triggers);
						log.info("\t\tTime_reset_triggers: " + mobility_params.time_reset_triggers);
						br.mark(1000);
						continue;
					}
					
					if (fields[0].equals("MATRIX")){							// MATRIX OF DISTANCES
						matrix_params = new ScannParams(Integer.parseInt(fields[1]),Integer.parseInt(fields[2]),Integer.parseInt(fields[3]),Integer.parseInt(fields[4]),Integer.parseInt(fields[5]),"");
						log.info("ShowMatrixOfDistancedBs configured:");
						log.info("\t\tTime_to_start: " + matrix_params.time_to_start);
						log.info("\t\tReporting_period: " + matrix_params.reporting_period);
						log.info("\t\tScanning_interval: " + matrix_params.scanning_interval);
						log.info("\t\tAdded_time: " + matrix_params.added_time);
						log.info("\t\tChannel: " + matrix_params.channel);
						br.mark(1000);
						continue;
					}

					if (fields[0].equals("INTERFERENCES")){							// INTERFERENCES
                        if(fields.length==6){// Filename added in poolfile
                            interference_params = new ScannParams(Integer.parseInt(fields[1]),Integer.parseInt(fields[2]),Integer.parseInt(fields[3]),Integer.parseInt(fields[4]),Integer.parseInt("0"),fields[5]);
						}else{// Not filename added in poolfile
                            interference_params = new ScannParams(Integer.parseInt(fields[1]),Integer.parseInt(fields[2]),Integer.parseInt(fields[3]),Integer.parseInt(fields[4]),Integer.parseInt("0"),"");
						}
						log.info("ShowScannedStationsStatistics configured:");
						log.info("\t\tTime_to_start: " + interference_params.time_to_start);
						log.info("\t\tReporting_period: " + interference_params.reporting_period);
						log.info("\t\tScanning_interval: " + interference_params.scanning_interval);
						log.info("\t\tAdded_time: " + interference_params.added_time);
						if(interference_params.filename.length()>0){
                            log.info("\t\tFilename: " + interference_params.filename);
                        }else{
                            log.info("\t\tFilename not assigned");
                        }
						br.mark(1000);
						continue;
					}
					
					if (fields[0].equals("CHANNEL")){							// CHANNEL ASSIGNMENT
					    if(fields.length==12){// Filename added in poolfile
                          channel_params = new ChannelAssignmentParams(Integer.parseInt(fields[1]),Integer.parseInt(fields[2]),Integer.parseInt(fields[3]),Integer.parseInt(fields[4]),Integer.parseInt(fields[5]),Integer.parseInt(fields[6]),Integer.parseInt(fields[7]), Integer.parseInt(fields[8]), Double.parseDouble(fields[9]), fields[10], fields[11]);
                        }else{
                          channel_params = new ChannelAssignmentParams(Integer.parseInt(fields[1]),Integer.parseInt(fields[2]),Integer.parseInt(fields[3]),Integer.parseInt(fields[4]),Integer.parseInt(fields[5]),Integer.parseInt(fields[6]),Integer.parseInt(fields[7]), Integer.parseInt(fields[8]), Double.parseDouble(fields[9]), fields[10], "");
                        }
						log.info("ChannelAssignment configured:");
						log.info("\t\tTime_to_start: " + channel_params.time_to_start);
						log.info("\t\tPause between scans: " + channel_params.pause);
						log.info("\t\tScanning_interval: " + channel_params.scanning_interval);
						log.info("\t\tAdded_time: " + channel_params.added_time);
						log.info("\t\tNumber of scans: " + channel_params.number_scans);
						log.info("\t\tIdle time: " + channel_params.idle_time);
						log.info("\t\tChannel: " + channel_params.channel);
						log.info("\t\tMethod: " + channel_params.method);
						log.info("\t\tThreshold: " + channel_params.threshold);
						log.info("\t\tMode: " + channel_params.mode);
						if(channel_params.filename.length()>0){
                            log.info("\t\tFilename: " + channel_params.filename);
                        }else{
                            log.info("\t\tFilename not assigned");
                        }
						br.mark(1000);
						continue;
					}
					
					if (fields[0].equals("SMARTAPSELECTION")){							// SMART AP SELECTION
                        if(fields.length==12){// Filename added in poolfile
                            smartap_params = new SmartApSelectionParams(Integer.parseInt(fields[1]),Integer.parseInt(fields[2]),Integer.parseInt(fields[3]),Double.parseDouble(fields[4]),Long.parseLong(fields[5]), Double.parseDouble(fields[6]),Integer.parseInt(fields[7]), fields[8],Integer.parseInt(fields[9]), Double.parseDouble(fields[10]), fields[11]);
                        }else{
                            smartap_params = new SmartApSelectionParams(Integer.parseInt(fields[1]),Integer.parseInt(fields[2]),Integer.parseInt(fields[3]),Double.parseDouble(fields[4]),Long.parseLong(fields[5]), Double.parseDouble(fields[6]),Integer.parseInt(fields[7]), fields[8],Integer.parseInt(fields[9]), Double.parseDouble(fields[10]), "");
                        }
						log.info("SmartApSelection configured:");
						log.info("\t\tTime_to_start: " + smartap_params.time_to_start);
						log.info("\t\tScanning_interval: " + smartap_params.scanning_interval);
						log.info("\t\tAdded_time: " + smartap_params.added_time);
						log.info("\t\tSignal_threshold: " + smartap_params.signal_threshold);
						log.info("\t\tHysteresis_threshold: " + smartap_params.hysteresis_threshold);
						log.info("\t\tPrevius_data_weight (alpha): " + smartap_params.weight);
						log.info("\t\tPause between scans: " + smartap_params.pause);
						log.info("\t\tMode: " + smartap_params.mode);
						log.info("\t\tTxpowerSTA: " + smartap_params.txpowerSTA);
						log.info("\t\tThReqSTA: " + smartap_params.thReqSTA);
						if(smartap_params.filename.length()>0){
                            log.info("\t\tFilename: " + smartap_params.filename);
                        }else{
                            log.info("\t\tFilename not assigned");
                        }
						br.mark(1000);
						continue;
					}
					
					if (fields[0].equals("SMARTAPSELECTIONTEXT")){							// SMART AP SELECTION TEXT
                        if(fields.length==12){// Filename added in poolfile
                            smartap_text_params = new SmartApSelectionTextParams(Integer.parseInt(fields[1]),Integer.parseInt(fields[2]),Integer.parseInt(fields[3]),Double.parseDouble(fields[4]),Long.parseLong(fields[5]), Double.parseDouble(fields[6]),Integer.parseInt(fields[7]), fields[8],Integer.parseInt(fields[9]), Double.parseDouble(fields[10]), fields[11]);
                        }else{
                            smartap_text_params = new SmartApSelectionTextParams(Integer.parseInt(fields[1]),Integer.parseInt(fields[2]),Integer.parseInt(fields[3]),Double.parseDouble(fields[4]),Long.parseLong(fields[5]), Double.parseDouble(fields[6]),Integer.parseInt(fields[7]), fields[8],Integer.parseInt(fields[9]), Double.parseDouble(fields[10]), "");
                        }
						log.info("SmartApSelectionText configured:");
						log.info("\t\tTime_to_start: " + smartap_text_params.time_to_start);
						log.info("\t\tScanning_interval: " + smartap_text_params.scanning_interval);
						log.info("\t\tAdded_time: " + smartap_text_params.added_time);
						log.info("\t\tSignal_threshold: " + smartap_text_params.signal_threshold);
						log.info("\t\tHysteresis_threshold: " + smartap_text_params.hysteresis_threshold);
						log.info("\t\tPrevius_data_weight (alpha): " + smartap_text_params.weight);
						log.info("\t\tPause between scans: " + smartap_text_params.pause);
						log.info("\t\tMode: " + smartap_text_params.mode);
						log.info("\t\tTxpowerSTA: " + smartap_text_params.txpowerSTA);
						log.info("\t\tThReqSTA: " + smartap_text_params.thReqSTA);
						if(smartap_text_params.filename.length()>0){
                            log.info("\t\tFilename: " + smartap_text_params.filename);
                        }else{
                            log.info("\t\tFilename not assigned");
                        }
						br.mark(1000);
						continue;
					}
					
					if (fields[0].equals("VIPAP")){							// VIP AGENT
						vip_ap_ip_address = fields[1];
						log.info("VIP AP ip address " + vip_ap_ip_address);
						br.mark(1000);
						continue;
					}
					
					if (fields[0].equals("NAME")){									// NEW POOL
						br.reset();
						break;
					}
					// Error in poolfile
					log.error("Optional field error");
					log.error("Offending line: " + strLine);
					System.exit(1);	
				}
			}

      br.close();

		} catch (FileNotFoundException e1) {
			log.error("Agent authentication list (config option poolFile) not supplied. Terminating.");
			System.exit(1);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		} catch (InstantiationException e) {
			e.printStackTrace();
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		}

        // Static client - lvap assignments
        String clientListFile = DEFAULT_CLIENT_LIST_FILE;
        String clientListFileConfig = configOptions.get("clientList");

        if (clientListFileConfig != null) {
            clientListFile = clientListFileConfig;
        }

        try {
			BufferedReader br = new BufferedReader (new FileReader(clientListFile));

			String strLine;

			while ((strLine = br.readLine()) != null) {
				String [] fields = strLine.split(" ");

				MACAddress hwAddress = MACAddress.valueOf(fields[0]);
				InetAddress ipaddr = InetAddress.getByName(fields[1]);

				ArrayList<String> ssidList = new ArrayList<String> ();
				ssidList.add(fields[3]); // FIXME: assumes a single ssid
				Lvap lvap = new Lvap(MACAddress.valueOf(fields[2]), ssidList);

				log.info("Adding client: " + fields[0] + " " + fields[1] + " " +fields[2] + " " +fields[3]);
				clientManager.addClient(hwAddress, ipaddr, lvap);
				lvap.setOFMessageList(lvapManager.getDefaultOFModList(ipaddr));
			}

      br.close();

		} catch (FileNotFoundException e) {
			// skip
		} catch (IOException e) {
			e.printStackTrace();
		}

        // Lvap timeout, port, and ssid-list
        String timeoutStr = configOptions.get("idleLvapTimeout");
        if (timeoutStr != null) {
        	int timeout = Integer.parseInt(timeoutStr);

        	if (timeout > 0) {
        		idleLvapTimeout = timeout;
        	}
        }

        int port = DEFAULT_PORT;
        String portNum = configOptions.get("masterPort");
        if (portNum != null) {
            port = Integer.parseInt(portNum);
        }

        IThreadPoolService tp = context.getServiceImpl(IThreadPoolService.class);
        executor = tp.getScheduledExecutor();
        // Spawn threads for different services
        executor.execute(new OdinAgentProtocolServer(this, port, executor));

        try{
	        // Spawn applications
	        for (OdinApplication app: applicationList) {

	        	executor.execute(app);
	        }
        }catch(Exception ex){
        	ex.printStackTrace();
        }

	}

	/** IOFSwitchListener methods **/

	@Override
	public void addedSwitch(IOFSwitch sw) {
		// inform-agent manager
	}

	@Override
	public String getName() {
		return "OdinMaster";
	}

	@Override
	public void removedSwitch(IOFSwitch sw) {
		// Not all OF switches are Odin agents. We should immediately remove
		// any associated Odin agent then.
		final InetAddress switchIpAddr = ((InetSocketAddress) sw.getChannel().getRemoteAddress()).getAddress();
		agentManager.removeAgent(switchIpAddr);
	}

/*
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		return Command.CONTINUE;
	}
*/
	
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

	// We use this to pick up DHCP response frames
	// and update a client's IP address details accordingly
	// we use the update_client_lvap function to send the IP address once the DHCP server has assigned it to the STA
	Ethernet frame = IFloodlightProviderService.bcStore.get(cntx,
        IFloodlightProviderService.CONTEXT_PI_PAYLOAD);

	IPacket payload = frame.getPayload(); // IP
        if (payload == null)
        	return Command.CONTINUE;

        IPacket p2 = payload.getPayload(); // TCP or UDP

        if (p2 == null)
        	return Command.CONTINUE;
        IPacket p3 = p2.getPayload(); // Application
        if ((p3 != null) && (p3 instanceof DHCP)) {
        	DHCP packet = (DHCP) p3;
        	try {

			//log.info("DHCP packet received...");
        		final MACAddress clientHwAddr = MACAddress.valueOf(packet.getClientHardwareAddress());
        		final OdinClient oc = clientManager.getClients().get(clientHwAddr);

    			// Don't bother if we're not tracking the client
        		// or if the client is unassociated with the agent
        		// or the agent's switch hasn't been registered yet
        		if (oc == null || oc.getLvap().getAgent() == null || oc.getLvap().getAgent().getSwitch() == null) {
        			return Command.CONTINUE;
        		}

			//log.info("*** DHCP packet *for our client* received... *** ");

        		// Look for the Your-IP field in the DHCP packet
        		if (packet.getYourIPAddress() != 0) {

        			// int -> byte array -> InetAddr
        			final byte[] arr = ByteBuffer.allocate(4).putInt(packet.getYourIPAddress()).array();
        			final InetAddress yourIp = InetAddress.getByAddress(arr);

        			// No need to invoke agent update protocol if the node
        			// is assigned the same IP
        			if (yourIp.equals(oc.getIpAddress())) {
        				return Command.CONTINUE;
        			}

        			log.info("Updating client: " + clientHwAddr + " with ipAddr: " + yourIp);
        			oc.setIpAddress(yourIp);
        		/*	oc.getLvap().setOFMessageList(lvapManager.getDefaultOFModList(yourIp));

        			// Push flow messages associated with the client
        			try {
        				oc.getLvap().getAgent().getSwitch().write(oc.getLvap().getOFMessageList(), null);
        			} catch (IOException e) {
        				log.error("Failed to update switch's flow tables " + oc.getLvap().getAgent().getSwitch());
        			}*/
        			oc.getLvap().getAgent().updateClientLvap(oc);
        		}

			} catch (UnknownHostException e) {
				// Shouldn't ever happen
				e.printStackTrace();
			}
        }

		return Command.CONTINUE;
	}
	

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	/**
	 * Push the subscription list to the agent
	 *
	 * @param oa agent to push subscription list to
	 */
	private void pushSubscriptionListToAgent (final IOdinAgent oa) {
		oa.setSubscriptions(subscriptionList);
	}

	private void updateAgentLastHeard (InetAddress odinAgentAddr) {
		IOdinAgent agent = agentManager.getAgent(odinAgentAddr);

		if (agent != null) {
			// Update last-heard for failure detection
			agent.setLastHeard(System.currentTimeMillis());
		}
	}

	private class OdinAgentLvapAddRunnable implements Runnable {
		final IOdinAgent oa;
		final OdinClient oc;

		OdinAgentLvapAddRunnable(IOdinAgent newAgent, OdinClient oc) {
			this.oa = newAgent;
			this.oc = oc;
		}
		@Override
		public void run() {
			oa.addClientLvap(oc);
		}

	}

	private class OdinAgentLvapRemoveRunnable implements Runnable {
		final IOdinAgent oa;
		final OdinClient oc;

		OdinAgentLvapRemoveRunnable(IOdinAgent oa, OdinClient oc) {
			this.oa = oa;
			this.oc = oc;
		}
		@Override
		public void run() {
			oa.removeClientLvap(oc);
		}

	}

	private class OdinAgentSendProbeResponseRunnable implements Runnable {
		final IOdinAgent oa;
		final MACAddress clientHwAddr;
		final MACAddress bssid;
		final Set<String> ssidList;

		OdinAgentSendProbeResponseRunnable(IOdinAgent oa, MACAddress clientHwAddr, MACAddress bssid, Set<String> ssidList) {
			this.oa = oa;
			this.clientHwAddr = clientHwAddr;
			this.bssid = bssid;
			this.ssidList = ssidList;
		}
		@Override
		public void run() {
			oa.sendProbeResponse(clientHwAddr, bssid, ssidList);
		}

	}

	private class IdleLvapReclaimTask implements Runnable {
		private final OdinClient oc;

		IdleLvapReclaimTask(final OdinClient oc) {
			this.oc = oc;
		}

		@Override
		public void run() {
			OdinClient client = clientManager.getClients().get(oc.getMacAddress());

			if (client == null) {
				return;
			}

			// Client didn't follow through to connect - no assoc message received in the master

			if(client.getLvap().getAssocState() == false){
				IOdinAgent agent = client.getLvap().getAgent();

				if (agent != null) {
					log.info("Clearing Lvap " + client.getMacAddress() +
							" from agent:" + agent.getIpAddress() + " due to association not completed");
					poolManager.removeClientPoolMapping(client);
					agent.removeClientLvap(client);
					clientManager.removeClient(client.getMacAddress());
				}

			 }else{
					//log.info("Association state of client " + client.getMacAddress() + " is " + client.getLvap().getAssocState());
			 }

/* Original code
			// Client didn't follow through to connect
			try {
				if (client.getIpAddress().equals(InetAddress.getByName("0.0.0.0"))) {
					IOdinAgent agent = client.getLvap().getAgent();

					if (agent != null) {
						//log.info("Clearing Lvap " + client.getMacAddress() +
						//		" from agent:" + agent.getIpAddress() + " due to inactivity");
						//poolManager.removeClientPoolMapping(client);
						//agent.removeClientLvap(client);
						//clientManager.removeClient(client.getMacAddress());
					}
				}

			} catch (UnknownHostException e) {
				// skip
			}
*/
		}
	}

	private class SubscriptionCallbackTuple {
		OdinEventSubscription oes;
		NotificationCallback cb;
	}

	private class FlowDetectionCallbackTuple {
		OdinEventFlowDetection oefd;
		FlowDetectionCallback cb;
	}
	
	public class MobilityParams {
		public int time_to_start;
		public long idle_client_threshold;
		public long hysteresis_threshold;
		public long signal_threshold;
		public int scanning_time;
		public int number_of_triggers;
		public long time_reset_triggers;

		public MobilityParams (int time_to_start, long idle_client_threshold, long hysteresis_threshold, long signal_threshold,	int scanning_time, int number_of_triggers, long time_reset_triggers) {
			this.time_to_start = time_to_start*1000;
			this.idle_client_threshold = idle_client_threshold*1000;
			this.hysteresis_threshold = hysteresis_threshold*1000;
			this.signal_threshold = signal_threshold+256;
			this.scanning_time = scanning_time*1000;
			this.number_of_triggers = number_of_triggers;
			this.time_reset_triggers = time_reset_triggers*1000;
		}
	}
	
	public class ScannParams {
		public int time_to_start;
		public int reporting_period;
		public int scanning_interval;
		public int added_time;
		public int channel;
		public String filename;

		public ScannParams (int time_to_start, int reporting_period, int scanning_interval, int added_time,	int channel, String filename) {
			this.time_to_start = time_to_start*1000;
			this.reporting_period = reporting_period*1000;
			this.scanning_interval = scanning_interval*1000;
			this.added_time = added_time*1000;
			this.channel = channel;
			this.filename = filename;
		}
	}
	
	public class ChannelAssignmentParams {
		public int time_to_start;
		public int pause;
		public int scanning_interval;
		public int added_time;
		public int number_scans;
		public int idle_time;
		public int channel;
		public int method;
		public Double threshold;
		public String mode;
		public String filename;

		public ChannelAssignmentParams (int time_to_start, int pause, int scanning_interval, int added_time, int number_scans, int idle_time, int channel, int method, Double threshold, String mode, String filename) {
			this.time_to_start = time_to_start*1000;
			this.pause = pause*1000;
			this.scanning_interval = scanning_interval*1000;
			this.added_time = added_time*1000;
			this.number_scans = number_scans;
			this.idle_time = idle_time;
			this.channel = channel;
			this.method = method;
			this.threshold = threshold;
			this.mode = mode;
			this.filename = filename;
		}
	}
	
	public class SmartApSelectionParams {
		public int time_to_start;
		public int scanning_interval;
		public int added_time;
		public Double signal_threshold;
		public long hysteresis_threshold;
		public Double weight;
		public int pause;
		public String mode;
		public int txpowerSTA;
		public Double thReqSTA;
		public String filename;

		public SmartApSelectionParams (int time_to_start, int scanning_interval, int added_time, Double signal_threshold, long hysteresis_threshold, Double weight, int pause, String mode, int txpowerSTA, Double thReqSTA, String filename) {
			this.time_to_start = time_to_start*1000;
			this.scanning_interval = scanning_interval;
			this.added_time = added_time;
			this.signal_threshold = signal_threshold;
			this.hysteresis_threshold = hysteresis_threshold;
			this.weight = weight;
			this.pause = pause*1000;
            this.mode = mode;
            this.txpowerSTA = txpowerSTA;
			this.thReqSTA = thReqSTA;
			this.filename = filename;
		}
	}

		public class SmartApSelectionTextParams {
		public int time_to_start;
		public int scanning_interval;
		public int added_time;
		public Double signal_threshold;
		public long hysteresis_threshold;
		public Double weight;
		public int pause;
		public String mode;
		public int txpowerSTA;
		public Double thReqSTA;
		public String filename;

		public SmartApSelectionTextParams (int time_to_start, int scanning_interval, int added_time, Double signal_threshold, long hysteresis_threshold, Double weight, int pause, String mode, int txpowerSTA, Double thReqSTA, String filename) {
			this.time_to_start = time_to_start*1000;
			this.scanning_interval = scanning_interval;
			this.added_time = added_time;
			this.signal_threshold = signal_threshold;
			this.hysteresis_threshold = hysteresis_threshold;
			this.weight = weight;
			this.pause = pause*1000;
            this.mode = mode;
            this.txpowerSTA = txpowerSTA;
			this.thReqSTA = thReqSTA;
			this.filename = filename;
		}
	}

 	@Override
	public IStorageSourceService getStorageService() {
		return storageSourceService;
	}

}
