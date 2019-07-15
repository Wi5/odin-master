package net.floodlightcontroller.odin.applications;

import net.floodlightcontroller.util.MACAddress;

public class SmartApSelectionHelper {
	
	  public static double calculateFittingnessFactor(double Rreq, double Rb){

		    double shaping = 5, shaping_k = 1, shaping_mine = 1.3, ff = 0;

		    if(Math.abs(Rb) > 1e-6){
		      double U = Math.pow(Rb * shaping_mine/Rreq, shaping) / (1 + Math.pow(Rb*shaping_mine/Rreq, shaping));
		      double lambda = 1 - Math.pow(Math.E, -shaping_k / (Math.pow(shaping-1, 1/shaping) + Math.pow(shaping-1, (1-shaping)/shaping)));
		      ff = (1 - Math.pow(Math.E, -shaping_k * U / (Rb * shaping_mine / Rreq))) / lambda;
		    }
		    return ff;
		  }
	  
	  public static Double getRssiFromRxStats(MACAddress clientMAC, String arr){ // Process the string with all the data, it saves 2 ms if done inside the app vs. in agent

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
	  
	  public static double calculateT2(int numberOfStas, double tValue){
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
	  
	  public static double[] getTransmissionTime(double avgRate){ // Returns transmission times to calculate THavg
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
	  
	  public static double getOFDMRates(double SNR){ // Returns ODFM rates to calculate THavg
	
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
}
