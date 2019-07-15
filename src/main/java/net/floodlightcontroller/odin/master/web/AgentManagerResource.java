package net.floodlightcontroller.odin.master.web;

import java.io.IOException;
import java.net.InetAddress;
import java.util.List;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.io.PrintStream;
import java.io.File;
import java.util.Set;


import net.floodlightcontroller.odin.applications.odinApplicationsStorage.OdinAgentStorage;
import net.floodlightcontroller.odin.applications.odinApplicationsStorage.SmartApSelectionStorage;
import net.floodlightcontroller.odin.master.*;
import net.floodlightcontroller.storage.IStorageSourceService;

import org.restlet.resource.Get;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.restlet.resource.ResourceException;
import com.google.gson.*;

public class AgentManagerResource extends ServerResource {

	@Get("json")
    public List<OdinAgentStorage> retreive() {

		OdinMaster oc = (OdinMaster) getContext().getAttributes().
				get(OdinMaster.class.getCanonicalName());

		List<OdinAgentStorage> res = new ArrayList<OdinAgentStorage>();

		Set<InetAddress> agentsAddress = oc.getAgentAddrs(PoolManager.GLOBAL_POOL);

        for (InetAddress agentAddr : agentsAddress) {

      		int chann = oc.getChannelFromAgent(PoolManager.GLOBAL_POOL,agentAddr);
			long lastheard =  oc.getLastHeardFromAgent(PoolManager.GLOBAL_POOL,agentAddr);
	    	int txPower = oc.getTxPowerFromAgent(PoolManager.GLOBAL_POOL, agentAddr);

	    	int numberOfClients = oc.getClientsFromAgent(PoolManager.GLOBAL_POOL, agentAddr).size();

	    	// FIXME: the SSID is hardcoded here and it should not
	    	OdinAgentStorage newAgent = new OdinAgentStorage(agentAddr, lastheard, chann, "wi5orange", lastheard, txPower, numberOfClients);

	    	res.add(newAgent);
		}		

		return res;
	}

	
	@Post
	public void AgentChangeChannelResource(String mapApIpAddress){
		OdinMaster oc = (OdinMaster) getContext().getAttributes().
				get(OdinMaster.class.getCanonicalName());
		
		MapApIddress fmdata;
		if(mapApIpAddress == null) {
			throw new ResourceException(400);
		}

		try {
            Gson gson = new GsonBuilder().create();
            fmdata = gson.fromJson(mapApIpAddress, MapApIddress.class);
			
			String apIpAddress = fmdata.getApIpAddress();
			int channel= fmdata.getChannel();

			oc.setChannelToAgent("", InetAddress.getByName(apIpAddress), channel);
		} catch (Exception ex) {
			throw new ResourceException(400);
		}
	}
	
	static class MapApIddress {
		
		private String apIpAddress;
		private int channel;
		
		public String getApIpAddress() {
			return apIpAddress;
		}

		public void setApIpAddress(String apIpAddress) {
			this.apIpAddress = apIpAddress;
		}

		public int getChannel() {
			return channel;
		}

		public void setChannel(int channel) {
			this.channel = channel;
		}

		public MapApIddress(String apIpAddress, int channel) {
			this.apIpAddress = apIpAddress;
			this.channel = channel;
		}
	}
}