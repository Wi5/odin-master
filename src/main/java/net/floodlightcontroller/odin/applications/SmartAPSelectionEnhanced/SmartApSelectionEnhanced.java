package net.floodlightcontroller.odin.applications;

import java.net.InetAddress;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.Arrays;
import java.io.File;
import java.io.PrintStream;

import net.floodlightcontroller.odin.applications.SmartApSelectionHelper;

import net.floodlightcontroller.odin.applications.odinApplicationsStorage.OdinClientStorage;
import net.floodlightcontroller.odin.applications.odinApplicationsStorage.SmartApSelectionStorage;
import net.floodlightcontroller.odin.master.OdinApplication;
import net.floodlightcontroller.odin.master.OdinClient;
import net.floodlightcontroller.odin.master.OdinEventFlowDetection;
import net.floodlightcontroller.odin.master.FlowDetectionCallback;
import net.floodlightcontroller.odin.master.FlowDetectionCallbackContext;
import net.floodlightcontroller.odin.master.OdinMaster.SmartApSelectionParams;
import net.floodlightcontroller.storage.IStorageSourceService;
import net.floodlightcontroller.util.MACAddress;

import java.util.Date;

import javax.swing.JOptionPane;

public class SmartApSelectionEnhanced extends OdinApplication {

	// IMPORTANT: this application only works if all the agents in the
	// poolfile are activated before the end of the INITIAL_INTERVAL.
	// Otherwise, the application looks for an object that does not exist
	// and gets stopped

	// SSID to scan
	private final String SCANNED_SSID = "*";

	// Params
	private SmartApSelectionParams SMARTAP_PARAMS;

	// Scanning agents
	Map<InetAddress, Integer> scanningAgents = new HashMap<InetAddress, Integer>();
	int result; // Result for scanning

	HashSet<OdinClient> clients;
	Set<InetAddress> agents;

	private int[] channels = null;
	private int num_channels = 0;
	private int num_agents = 0;
	private String[][] vals_rx = null;

	private SmartApSelectionStorage storage;

	private long time = 0L; // Compare timestamps in ms

	InetAddress nullAddr = null;
	InetAddress vipAPAddr = null;
	InetAddress nonVipAPAddr = null; // If the STA connects to VIP first, we
										// need to handoff to other AP

	private int vip_index = 0;
	/**
	 * Flow detection
	 */
	private final String IPSrcAddress; // Handle a IPSrcAddress or all
										// IPSrcAddress ("*")
	private final String IPDstAddress; // Handle a IPDstAddress or all
										// IPDstAddress ("*")
	private final int protocol; // Handle a protocol or all protocol ("*")
	private final int SrcPort; // Handle a SrcPort or all SrcPort ("*")
	private final int DstPort; // Handle a DstPort or all DstPort ("*")

	Map<InetAddress, DetectedFlow> flowsReceived = new HashMap<InetAddress, DetectedFlow>();

	public SmartApSelectionEnhanced() {
		this.IPSrcAddress = "*";
		this.IPDstAddress = "*";
		this.protocol = 0;
		this.SrcPort = 0;
		this.DstPort = 0;
	}

	/**
	 * Register flow detection
	 */
	private void initDetection() {
		OdinEventFlowDetection oefd = new OdinEventFlowDetection();
		oefd.setFlowDetection(this.IPSrcAddress, this.IPSrcAddress,
				this.protocol, this.SrcPort, this.DstPort);
		FlowDetectionCallback cb = new FlowDetectionCallback() {
			@Override
			public void exec(OdinEventFlowDetection oefd,
					FlowDetectionCallbackContext cntx) {
				flowsReceived = DetectedFlow.handler(flowsReceived,
						nonVipAPAddr, oefd, cntx);
			}
		};
		/*
		 * Before executing this line, make sure the agents declared in poolfile
		 * are started
		 */
		registerFlowDetection(oefd, cb);
	}

	/**
	 * Condition for a hand off
	 * 
	 * Example of params in poolfile imported in SMARTAP_PARAMS:
	 * 
	 * SMARTAP_PARAMS.HYSTERESIS_THRESHOLD = 4; SMARTAP_PARAMS.SIGNAL_THRESHOLD
	 * = -56;
	 * 
	 * With these parameters a hand off will start when:
	 * 
	 * The Rssi received from a specific client is below -56 dBm, there is
	 * another AP with better received Rssi and a previous hand off has not
	 * happened in the last 4000 ms
	 * 
	 */

	@Override
	public void run() {
		inicialice_Storage();

		JOptionPane.showConfirmDialog(null, "¿Ha lanzado los ap?",
				"NETWORK MONTADA", JOptionPane.DEFAULT_OPTION);

		// Write on file integration
		PrintStream ps = null;

		if (SMARTAP_PARAMS.filename.length() > 0) {
			File f = new File(SMARTAP_PARAMS.filename);
			try {
				ps = new PrintStream(f);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		agents = getAgents();
		num_agents = agents.size(); // Number of agents
		channels = new int[num_agents]; // Array to store the channels in use
		int[] channelsAux = new int[num_agents];

		try { // Create Ip to compare with clients not assigned
			nullAddr = InetAddress.getByName("0.0.0.0");
			vipAPAddr = InetAddress.getByName(getVipAPIpAddress());
		} catch (Exception e) {
			e.printStackTrace();
		}

		inicalize_agents(channelsAux);
		
		// Matrix to store the results from agents
		vals_rx = new String[num_channels][num_agents]; 
														
		// Map to store RSSI for each STA in all
		Map<MACAddress, Double[]> rssiData = new HashMap<MACAddress, Double[]>(); 
		// Map to store last handoff for each STA
		//FIXME: Maybe create APs structs
		Map<MACAddress, Long> handoffDate = new HashMap<MACAddress, Long>(); 
		// Map to store Throughput available for each STA in all APs struct

		Map<MACAddress, Double[]> ffData = new HashMap<MACAddress, Double[]>(); 

		initDetection(); // Register flow detection

		while (true) {
			loop(ps, rssiData, handoffDate, ffData);
		}
	}

	/**
	 * Codigo que se ejecuta en cada iteracion
	 * @param ps
	 * @param rssiData
	 * @param handoffDate
	 * @param ffData
	 * @param progressIndex
	 * @return
	 */
	private void loop(PrintStream ps, Map<MACAddress, Double[]> rssiData, Map<MACAddress, Long> handoffDate,	Map<MACAddress, Double[]> ffData) {
		try {
			Thread.sleep(100);

			clients = new HashSet<OdinClient>(getClients());

			int num_clients = clients.size(); // Number of STAs

			if (num_clients == 0) { // No clients, no need of scan
				return;
			}
			// Array with the indexes of channels, better performance in data process
			int[] clientsChannels = new int[num_clients]; 

			//Se crea el array de STA
			createClientsArray(clientsChannels);

			time = System.currentTimeMillis();

			// Se solicitan los escaneos y se reciben los datos de estos
			handleScan();

			// All the statistics stored, now process
			time = System.currentTimeMillis();
			
			//Se procesan los datos obteniendo el RSSI suavizado y construyendo la matriz de atenuacion
			processClients(rssiData, clientsChannels);

			time = System.currentTimeMillis();
			InetAddress[] agentsArray = agents.toArray(new InetAddress[0]);
			
			//Se comprueba si es necesario realizar handoff ya sea mediante el balanceador basico o el modo FF
			handleHandoff(rssiData, handoffDate, ffData, agentsArray);
			
			//Se realizan acciones complementarias segun el algoritmo que se ejecute
			if (SMARTAP_PARAMS.mode.equals("FF")) { 
				// Show FF results and handoff if necessary
				mode_FF(handoffDate, ffData, agentsArray);
			}
			if (SMARTAP_PARAMS.mode.equals("BALANCER")) {
				mode_Balancer(rssiData, handoffDate, agentsArray);
			}

			if (SMARTAP_PARAMS.mode.equals("DETECTOR")) { 
				mode_Detector(rssiData);
			}
			ps.flush();
			// If a pause or a period is needed
			Thread.sleep(SMARTAP_PARAMS.pause); 

		} catch (Exception e) {
			e.printStackTrace();
			ps.close();
		}
	}

	// Metodo que inicializa la pasarela asincrona
	private void inicialice_Storage() {

		this.SMARTAP_PARAMS = getSmartApSelectionParams();

		IStorageSourceService storageSourceService = getStorageService();

		this.storage = new SmartApSelectionStorage(storageSourceService);

		storage.initStorage();

		storage.insertSmartApSelectionParams(this.SMARTAP_PARAMS);
	}

	/**
	 * Se realizan los calculos necesarios para obtener la señal de atunuacion suavizada.
	 * @param rssiData
	 * @param clientsChannels
	 * @param client_index
	 * @return
	 */
	private int processClients(Map<MACAddress, Double[]> rssiData,
			int[] clientsChannels) {
		int client_index = 0;
		int ind_aux;
		int client_channel;
		OdinClientStorage clientStorage;

		for (OdinClient oc : clients) {

			clientStorage = new OdinClientStorage(oc.getMacAddress()
					.toString(), oc.getIpAddress(), oc.getLvap());

			MACAddress eth = oc.getMacAddress(); // client MAC

			client_channel = clientsChannels[client_index]; // row in the matrix

			for (ind_aux = 0; ind_aux < num_agents; ind_aux++) {
				// String with "MAC rssi\nMAC rssi\n..."
				String arr = vals_rx[client_channel][ind_aux]; 
				
				// rssi or -99.9
				Double rssi = SmartApSelectionHelper.getRssiFromRxStats(eth, arr); 

				Double[] client_average_dBm = new Double[num_agents];

				client_average_dBm = rssiData.get(eth);

				if (client_average_dBm == null) {
					// First time STA is associated
					client_average_dBm = new Double[num_agents];
					Arrays.fill(client_average_dBm, -99.9);
					client_average_dBm[ind_aux] = rssi;

				} else {
					if ((client_average_dBm[ind_aux] != -99.9) && (client_average_dBm[ind_aux] != null)) {
						if (rssi != -99.9) {							
							//clientStorage.setRssi(rssi);
							Double client_signal = Math.pow(10.0,(rssi) / 10.0); // Linear power
							// Linear power average
							Double client_average = Math.pow(10.0,(client_average_dBm[ind_aux]) / 10.0); 
							client_average = client_average * (1 - SMARTAP_PARAMS.weight) + client_signal * SMARTAP_PARAMS.weight;
							// Average power in dBm with 2 decimals
							client_average_dBm[ind_aux] = Double.valueOf((double) Math.round(1000 * Math.log10(client_average)) / 100); 
						}
					} else {
						client_average_dBm[ind_aux] = rssi;
					}
				}
				clientStorage.setAverageDBM(client_average_dBm);
				rssiData.put(eth, client_average_dBm);
			}

			// UPDATE OR SAVE CLIENT ON STORAGEMANAGER
			clientStorage.setLastScanInfo(new Date().getTime());
			storage.insertOrSaveClient(clientStorage);

			client_index++;
		}
		return client_index;
	}
	
	private int handleHandoff(Map<MACAddress, Double[]> rssiData,Map<MACAddress, Long> handoffDate,Map<MACAddress, Double[]> ffData, InetAddress[] agentsArray) 
	{
		int client_index = 0;
		int ind_aux;
		for (OdinClient oc : clients) {
			client_index = 0;
			MACAddress eth = oc.getMacAddress(); // client MAC

			Double[] client_dBm = new Double[num_agents];

			InetAddress clientAddr = oc.getIpAddress();
			InetAddress agentAddr = oc.getLvap().getAgent().getIpAddress();

			if (clientAddr.equals(nullAddr))// If client not assigned, next one
				continue;
			
			client_dBm = rssiData.get(eth);

			if (client_dBm != null) {
				// Array with rssi
				Double maxRssi = client_dBm[0]; 
				// Start with first rssi
				Double currentRssi = null;
				
				for (ind_aux = 1; ind_aux < client_dBm.length; ind_aux++) {
					// Get max position, VIP AP not considered
					if ((client_dBm[ind_aux] > maxRssi)	&& (!vipAPAddr.equals(agentsArray[ind_aux]))) {
						maxRssi = client_dBm[ind_aux];
						client_index = ind_aux;
					}
				}

				if (!SMARTAP_PARAMS.mode.equals("FF")) { 
					calculeHandoffBalancer(handoffDate, client_index, agentsArray, eth, agentAddr, currentRssi);
				}
				if (SMARTAP_PARAMS.mode.equals("FF")) { // Calculate FF
					calculateFFData(ffData, oc, eth, client_dBm);
				}
			}
		}
		return client_index;
	}
	
	private void inicalize_agents(int[] channelsAux) {
		int ind_aux = 0;
		// Get channels from APs, assuming there is no change in all operation,
		// if already in array->0
		for (InetAddress agentAddr : agents) {

			int chann = getChannelFromAgent(agentAddr);
			Arrays.sort(channelsAux);
			// if already in array, not necessary to add it
			if (Arrays.binarySearch(channelsAux, chann) < 0) {
				channelsAux[num_channels] = chann;
				channels[num_channels] = chann;
			}

			if (agentAddr.equals(vipAPAddr)) {
				vip_index = ind_aux;
			} else {
				nonVipAPAddr = agentAddr;
			}
			num_channels++;
			ind_aux++;

		}
	}
	
	
	/**
	 * Create array with client channels and their indexes for better data processing
	 */		
	private void createClientsArray(int[] clientsChannels) {
		int client_index = 0;
		int ind_aux;
		int client_channel;
		for (OdinClient oc : clients) { 
			ind_aux = 0;
			client_channel = getChannelFromAgent(oc.getLvap()
					.getAgent().getIpAddress());
			for (int chann : channels) {
				if (chann == client_channel) {
					clientsChannels[client_index] = ind_aux;
					client_index++;
					break;
				}
				ind_aux++;
			}

		}
	}
	

	private void calculeHandoffBalancer(Map<MACAddress, Long> handoffDate, int client_index, InetAddress[] agentsArray, MACAddress eth,
			InetAddress agentAddr, Double currentRssi) 
	{
		// In BALANCER mode, it will assign STAs to APs always with higher RSSI
		// than threshold,so there is not ping pong effect
		if (!agentsArray[client_index].equals(agentAddr)) {
			// Change to the best RSSI, if Rssi threshold is reached, handoff
			if (currentRssi < SMARTAP_PARAMS.signal_threshold) {
				Long handoffTime = handoffDate.get(eth);
				// If Time threshold is reached, handoff
				if ((handoffTime == null)
						|| ((System.currentTimeMillis() - handoffTime
								.longValue()) / 1000 > SMARTAP_PARAMS.hysteresis_threshold)) {
					handoffClientToAp(eth, agentsArray[client_index]);
					handoffDate.put(eth, Long.valueOf(System.currentTimeMillis()));
				}
			}
		}
	}
	

	private void calculateFFData(Map<MACAddress, Double[]> ffData, OdinClient oc, MACAddress eth, Double[] client_dBm) {
		
		int ind_aux = 0;
		Double[] TH_av = new Double[num_agents];

		for (InetAddress agentAddrFF : agents) {
			// If associated
			if (oc.getLvap().getAgent().getIpAddress().equals(agentAddrFF)) {
				
				// Reception statistics
				Map<MACAddress, Map<String, String>> vals_rx_FF = getRxStatsFromAgent(agentAddrFF);
				Map<String, String> vals_entry_rx = vals_rx_FF.get(eth);
				
				if (vals_entry_rx != null) {					
					Double clientRate = Double.parseDouble(vals_entry_rx.get("avg_rate"));
					// t and T
					double[] tTValues = SmartApSelectionHelper.getTransmissionTime(clientRate.doubleValue());
					double p = 0.98 * (tTValues[1] / tTValues[0]);
					
					TH_av[ind_aux] = clientRate.doubleValue() * p;
				} else {
					TH_av[ind_aux] = 0.0;
				}

			} else { // Not associated

				double txpowerAP = Math.pow(10.0,
						(getTxPowerFromAgent(agentAddrFF)) / 10.0);
				double txpowerSTA = Math.pow(10.0,
						(SMARTAP_PARAMS.txpowerSTA) / 10.0);
				double rssiDL = client_dBm[ind_aux] + 10.0
						* Math.log10(txpowerAP / txpowerSTA);
				double snr = 90.0 + rssiDL;
				double maxRate = SmartApSelectionHelper.getOFDMRates(snr);
				double[] tTValues = SmartApSelectionHelper
						.getTransmissionTime(maxRate);

				HashSet<OdinClient> clients_FF = new HashSet<OdinClient>(
						getClientsFromAgent(agentAddrFF));
				double t2Value = SmartApSelectionHelper.calculateT2(
						clients_FF.size(), tTValues[0]);
				double p = 0.98 * (tTValues[1] / t2Value);
				TH_av[ind_aux] = maxRate * p;
			}
			ind_aux++;
		}
		// Save TH_av in map
		ffData.put(eth, TH_av);
	}	
	
	private void handleScan() {		
		for (int channel = 0; channel < num_channels; ++channel) {
			if (channels[channel] == 0)
				continue;

			int agent = 0;
			scanningAgents.clear();
			for (InetAddress agentAddr : agents) {
				// Request statistics
				result = requestScannedStationsStatsFromAgent(agentAddr,
						channels[channel], SCANNED_SSID);
				scanningAgents.put(agentAddr, result);
			}

			try {
				Thread.sleep(SMARTAP_PARAMS.scanning_interval
						+ SMARTAP_PARAMS.added_time);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}

			for (InetAddress agentAddr : agents) {
				// Reception statistics
				if (scanningAgents.get(agentAddr) == 0) {
					continue;
				}
				vals_rx[channel][agent] = getScannedStaRssiFromAgent(agentAddr);
				agent++;
			}
		}
	}	


	/**
	 *  If a flow is detected, the  STA is moved to the VIP AP
	 * @param rssiData
	 */

	// Metodo para el modo detector
	private void mode_Detector(Map<MACAddress, Double[]> rssiData) {

		for (OdinClient oc : clients) { // All clients
			MACAddress eth = oc.getMacAddress(); // client MAC
			InetAddress clientAddr = oc.getIpAddress(); // client IP

			if (flowsReceived.containsKey(clientAddr)) {
				DetectedFlow cntx = flowsReceived.get(clientAddr);
				// Clean flow after 30 sec
				if ((System.currentTimeMillis() - cntx.timeStamp) > 30000) { 
					flowsReceived.remove(clientAddr);
					handoffClientToAp(eth, cntx.lastAgentAddr);
				} else {
					InetAddress agentAddr = oc.getLvap().getAgent()
							.getIpAddress();
					if (!vipAPAddr.equals(agentAddr)) {
						Double[] client_dBm = rssiData.get(eth);
						if (client_dBm[vip_index] > SMARTAP_PARAMS.signal_threshold) {
							cntx.lastAgentAddr = agentAddr;
							flowsReceived.put(clientAddr, cntx);
							handoffClientToAp(eth, vipAPAddr);
						}
					}
				}
			}
		}
		for (OdinClient oc : getClientsFromAgent(vipAPAddr)) { // In case STA is
																// associated
																// before the
																// app stars
			MACAddress eth = oc.getMacAddress(); // client MAC
			InetAddress clientAddr = oc.getIpAddress(); // client IP
			if (!flowsReceived.containsKey(clientAddr)) {
				handoffClientToAp(eth, nonVipAPAddr);
			}
		}
	}
	

	// Metodo para modo Balanceo
	private void mode_Balancer(Map<MACAddress, Double[]> rssiData, Map<MACAddress, Long> handoffDate, InetAddress[] agentsArray) {
		
		// Very simple balancer algorithm
		Map<MACAddress, InetAddress> assignedClients = simpleBalancerAlgorithm(rssiData, agentsArray, clients, SMARTAP_PARAMS.signal_threshold);

		for (MACAddress eth : assignedClients.keySet()) {
			Long handoffTime = handoffDate.get(eth);
			OdinClient clientHandoff = getClientFromHwAddress(eth);
			if (clientHandoff == null)
				continue;
			
			if ((handoffTime == null)
					|| ((System.currentTimeMillis() - handoffTime.longValue()) / 1000 > SMARTAP_PARAMS.hysteresis_threshold)) {
				InetAddress assignedAgent = assignedClients.get(eth);
				handoffClientToAp(eth, assignedAgent);
				handoffDate.put(eth, Long.valueOf(System.currentTimeMillis()));
			}
		}
	}

	
	private void mode_FF(Map<MACAddress, Long> handoffDate, Map<MACAddress, Double[]> ffData,InetAddress[] agentsArray) {
		int client_index;
		int ind_aux;
		for (OdinClient oc : clients) {
			client_index = 0;
			MACAddress eth = oc.getMacAddress(); // client MAC
			InetAddress clientAddr = oc.getIpAddress();
			InetAddress agentAddr = oc.getLvap().getAgent().getIpAddress();

			if (clientAddr.equals(nullAddr))// If client not assigned, next one
				continue;

			Double[] th_avFF = ffData.get(eth);
			Double maxFF = SmartApSelectionHelper.calculateFittingnessFactor(
					SMARTAP_PARAMS.thReqSTA, th_avFF[0]); // Start with first
															// Th_av
			Double currentTh_av = null;
			for (ind_aux = 1; ind_aux < th_avFF.length; ind_aux++) {// Get max
																	// position
																	// and
																	// calculate
																	// FF
				Double currentFF = SmartApSelectionHelper
						.calculateFittingnessFactor(SMARTAP_PARAMS.thReqSTA,
								th_avFF[ind_aux]);
				if (currentFF > maxFF) {
					maxFF = currentFF;
					client_index = ind_aux;
				}
			}
			for (ind_aux = 0; ind_aux < th_avFF.length; ind_aux++) {
				if (agentsArray[ind_aux].equals(agentAddr)) { // Current AP
					currentTh_av = th_avFF[ind_aux];
				}
			}

			if (!agentsArray[client_index].equals(agentAddr)) { // Change to the
																// best FF
				Long handoffTime = handoffDate.get(eth);
				// If Time threshold is reached, handoff
				if ((handoffTime == null)
						|| ((System.currentTimeMillis() - handoffTime
								.longValue()) / 1000 > SMARTAP_PARAMS.hysteresis_threshold)) {
					if (!(currentTh_av == 0.0)) {
						handoffClientToAp(eth, agentsArray[client_index]);
						handoffDate.put(eth,
								Long.valueOf(System.currentTimeMillis()));
					}
				}
			}
		}
	}
	
	/**
	 * Algoritmo balanceador simple
	 * @param handoffDate
	 * @param ffData
	 * @param client_index
	 * @param agentsArray
	 * @return
	 */

	private Map<MACAddress, InetAddress> simpleBalancerAlgorithm(Map<MACAddress, Double[]> rssiData, InetAddress[] agentsArray, HashSet<OdinClient> clients, Double threshold) 
	{ 
		// Print load in each AP and returns array of agents to assign
		int ind_aux = 0;
		int agent_index = 0;
		int max_index = 0;
		int[] numStasPerAgent = new int[agentsArray.length];
		boolean orderHandoff = false;
		Map<MACAddress, InetAddress> arrayHandoff = new HashMap<MACAddress, InetAddress>();

		HashSet<OdinClient> clients_Balancer;

		int maxStas = 0;
		int minStas = Integer.MAX_VALUE;
		int numberOfAgentsAvailable = 0;
		int num_clients = clients.size();
		
		// Create array with number of STAs for each AP, find the one with lower number
		for (InetAddress agentAddrBalancer : agentsArray) { 

			clients_Balancer = new HashSet<OdinClient>(
					getClientsFromAgent(agentAddrBalancer));

			int numberOfStas = clients_Balancer.size();

			boolean stasToMove = false;

			numStasPerAgent[ind_aux] = numberOfStas;
			
			// If there is not a STA with enougth RSSI, not handoff
			for (MACAddress eth : rssiData.keySet()) { 
				Double[] client_dBm = rssiData.get(eth);
				if (client_dBm[ind_aux] > SMARTAP_PARAMS.signal_threshold) {
					stasToMove = true;
					break;
				}
			}

			if ((numberOfStas <= minStas) && (stasToMove)) {
				minStas = numberOfStas;
				agent_index = ind_aux;
			}
			if (numberOfStas >= maxStas) {
				maxStas = numberOfStas;
				max_index = ind_aux;
			}
			if (stasToMove)
				numberOfAgentsAvailable++;
			ind_aux++;
		}
		ind_aux = 0;
		float mean = (float) num_clients / numberOfAgentsAvailable;
		int meanStas = Math.round(mean);
		
		// Print APs and number of STAs associated at it
		for (InetAddress agentAddrBalancer : agentsArray) { 
			if ((ind_aux == agent_index)&& (numStasPerAgent[ind_aux] < meanStas) && (maxStas > meanStas)) { 
				// min<mean and max>mean try to handoff a STA
				orderHandoff = true;
				break;
			}
			ind_aux++;
		}
		OdinClient clientHandoff = null;
		if (orderHandoff) {
			clients_Balancer = new HashSet<OdinClient>(
					getClientsFromAgent(agentsArray[max_index]));
			double maxRssi = -99.9;
			for (OdinClient oc : clients_Balancer) {
				Double[] client_dBm = new Double[num_agents];
				MACAddress eth = oc.getMacAddress();
				InetAddress clientAddr = oc.getIpAddress();
				if (clientAddr.equals(nullAddr))// If client not assigned, next
												// one
					continue;
				client_dBm = rssiData.get(eth);
				if (client_dBm != null) {
					if ((client_dBm[agent_index] >= maxRssi)
							&& (client_dBm[agent_index] > SMARTAP_PARAMS.signal_threshold)) {
						maxRssi = client_dBm[agent_index];
						clientHandoff = oc;
					}
				}
			}
		}
		if (clientHandoff != null) {
			arrayHandoff.put(clientHandoff.getMacAddress(),
					agentsArray[agent_index]);
			System.out.print("\033[0;1m - Handoff ordered\033[00m");
		}
		return arrayHandoff;
	}
	
	/***
	 * Funcion auxiliar que imprime por pantalla la carga de los puntos de acceso.
	 * @param agentsArray
	 * @param vipAgent
	 */

	private void printAgentsLoad(InetAddress[] agentsArray, InetAddress vipAgent) { 

		int ind_aux = 0;
		int[] numStasPerAgent = new int[agentsArray.length];

		HashSet<OdinClient> clients_AP;

		for (InetAddress agentAddrAP : agentsArray) { // Create array with
														// number of STAs for
														// each AP

			clients_AP = new HashSet<OdinClient>(
					getClientsFromAgent(agentAddrAP));

			int numberOfStas = clients_AP.size();

			numStasPerAgent[ind_aux] = numberOfStas;

			ind_aux++;
		}
		ind_aux = 0;

		for (InetAddress agentAddrAP : agentsArray) { // Print APs and number of
														// STAs associated at it

			if (vipAgent.equals(agentAddrAP)) { // VIP agent
				if (numStasPerAgent[ind_aux] > 0) {
					System.out.print("[\033[48;5;3;1m  "+numStasPerAgent[ind_aux]+"   \033[00m]");
				} else {
					System.out.print("[\033[48;5;94m  "+numStasPerAgent[ind_aux]+"   \033[00m]");
				}
			} else {
				System.out.print("[  "+numStasPerAgent[ind_aux]+"   ]");
			}
			ind_aux++;
		}
	}
	
	

	public SmartApSelectionParams getParams() {
		return this.SMARTAP_PARAMS;
	}
}
