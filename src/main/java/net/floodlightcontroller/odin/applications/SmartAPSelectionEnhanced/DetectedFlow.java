package net.floodlightcontroller.odin.applications;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Map;

import net.floodlightcontroller.odin.master.FlowDetectionCallbackContext;
import net.floodlightcontroller.odin.master.OdinEventFlowDetection;

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

	  /**
	  * This method show detected flows
	  *
	  * @param oefd
	  * @param cntx
	  */
	  public static Map<InetAddress, DetectedFlow> handler (Map<InetAddress, DetectedFlow> flowsReceived, InetAddress nonVipAPAddr,OdinEventFlowDetection oefd, FlowDetectionCallbackContext cntx) {
	    
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
	    
	    DetectedFlow flowDetected = new DetectedFlow(IPSrcAddress,IPDstAddress,cntx.protocol,cntx.SrcPort,cntx.DstPort,cntx.odinAgentAddr,nonVipAPAddr,System.currentTimeMillis()) ;
	    
	    flowsReceived.put(IPSrcAddress, flowDetected);
	    return flowsReceived;
	  }
	
}
