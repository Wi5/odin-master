package net.floodlightcontroller.odin.applications.odinApplicationsStorage;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import net.floodlightcontroller.odin.master.OdinMaster.SmartApSelectionTextParams;
import net.floodlightcontroller.storage.IPredicate;
import net.floodlightcontroller.storage.IResultSet;
import net.floodlightcontroller.storage.IStorageSourceService;
import net.floodlightcontroller.storage.OperatorPredicate;
import net.floodlightcontroller.storage.StorageException;


public class SmartApSelectionTextStorage {
	
	private IStorageSourceService storageSourceService;
		
	public String SMARTAP_TEXT_PARAMS = "SMARTAP_TEXT_PARAMS";
	
	public String SMARTAP_TEXT_AGENTS = "SMARTAP_TEXT_AGENTS";
	
	public String SMARTAP_TEXT_CLIENTS = "SMARTAP_TEXT_CLIENTS";
	
	public SmartApSelectionTextStorage(IStorageSourceService storageSourceService) {
		this.storageSourceService = storageSourceService;
	}	
	
	public void initStorage(){
		try{
		//Parametros de la aplicacion		

			Set<String> columns = new HashSet<String>();
			columns.add("SMARTAP_TEXT_PARAMS");

			this.storageSourceService.createTable(SMARTAP_TEXT_PARAMS, columns);		
			
			//Agentes
			columns = new HashSet<String>();
			columns.add("agent");		
			
			this.storageSourceService.createTable(SMARTAP_TEXT_AGENTS, columns);			
			
			//Clientes
			Set<String> client_columns = new HashSet<String>();
			client_columns.add("MAC_CLIENT");
			client_columns.add("CLIENT");


			this.storageSourceService.createTable(SMARTAP_TEXT_CLIENTS, client_columns);
        	this.storageSourceService.setTablePrimaryKeyName(SMARTAP_TEXT_CLIENTS, "MAC_CLIENT");        

		
		}catch(Exception ex){
			ex.printStackTrace();
		}

	}	
	
	//OPERACIONES SOBRE TABLAS
	//TODO SI SE VA DE MADRE METER EN CLASES SEPARADAS
	
	//---------------------------------------------------------------------------------------------------------------------------------------------------
	//CLIENTES
	//---------------------------------------------------------------------------------------------------------------------------------------------------	
	public List<OdinClientStorage> getClients(){

		List<OdinClientStorage> clients = new ArrayList<OdinClientStorage>();
		
		IResultSet resultSet = this.storageSourceService.executeQuery(SMARTAP_TEXT_CLIENTS,null,null, null);
		
		while(resultSet.next()){
			Map<String, Object> res = resultSet.getRow();
			for (Map.Entry<String, Object> entry : res.entrySet())
			{
				if(entry.getKey().equals("CLIENT")){
					clients.add((OdinClientStorage)entry.getValue());					
				}
			}
		}
				
		return clients;	
	}




	public OdinClientStorage getClient(String hwAddress){

		IResultSet resultSet = this.storageSourceService.executeQuery(SMARTAP_TEXT_CLIENTS,null,null, null);	

		OdinClientStorage client;

		while(resultSet.next()){
			Map<String, Object> res = resultSet.getRow();
			for (Map.Entry<String, Object> entry : res.entrySet())
			{
				if(entry.getKey().equals("CLIENT")){					
					client = (OdinClientStorage)entry.getValue();
					if(client.getHwAddress().equals(hwAddress)){
						return client;
					}
				}
			}
		}
				
		return null;	
	}
	
	public void insertClient(OdinClientStorage client){
		Map<String, Object> rowToInsert = new HashMap<String, Object>();
		rowToInsert.put("MAC_CLIENT", client.getHwAddress());
		rowToInsert.put("CLIENT", client);
		
		storageSourceService.insertRow(SMARTAP_TEXT_CLIENTS, rowToInsert);
	}

	public void insertOrSaveClient(OdinClientStorage client){
		if(getClient(client.getHwAddress())!=null){
			updateClient(client);
		}
		else{
			insertClient(client);
		}

	}

	public void updateClient(OdinClientStorage client){
		try{			
			Map<String, Object> updateClient = new HashMap<String, Object>();
			updateClient.put("MAC_CLIENT", client.getHwAddress());
			updateClient.put("CLIENT", client);


	        IPredicate predicate = new OperatorPredicate("MAC_CLIENT", OperatorPredicate.Operator.EQ, client.getHwAddress());
	        IResultSet resultSet = storageSourceService.executeQuery(SMARTAP_TEXT_CLIENTS, null, predicate, null);
	        while (resultSet.next()) {
	            storageSourceService.updateRow(SMARTAP_TEXT_CLIENTS, client.getHwAddress(), updateClient);
	        }
	        resultSet.close();
		} catch(Exception ex){
			ex.printStackTrace();
		}

	}



	//---------------------------------------------------------------------------------------------------------------------------------------------------
	//AGENTES
	//---------------------------------------------------------------------------------------------------------------------------------------------------

	public List<OdinAgentStorage> getAgents(){
			
		List<OdinAgentStorage> agents = new ArrayList<OdinAgentStorage>();
				
		IResultSet resultSet = this.storageSourceService.executeQuery("SMARTAP_TEXT_AGENTS",null,null, null);
		
		while(resultSet.next()){
			Map<String, Object> res = resultSet.getRow();
			for (Map.Entry<String, Object> entry : res.entrySet())
			{
				if(entry.getKey()!="id"){
					agents.add((OdinAgentStorage)entry.getValue());					
				}
			}
		}				
		return agents;
	}



	
	public void insertAgent(OdinAgentStorage agent){
		Map<String, Object> rowToInsert = new HashMap<String, Object>();		
		rowToInsert.put("agent", agent);
		
		storageSourceService.insertRow("SMARTAP_TEXT_AGENTS", rowToInsert);
	}
	
	//PARAMETROS
	public SmartApSelectionTextParams getParams(){
		SmartApSelectionTextParams params = null;
		IResultSet resultSet = this.storageSourceService.executeQuery("SMARTAP_TEXT_PARAMS",null,null, null);
		if(resultSet.next()){
			Map<String, Object> res = resultSet.getRow();
			for (Map.Entry<String, Object> entry : res.entrySet())
			{
				if(entry.getKey()!="id"){
					params = (SmartApSelectionTextParams)entry.getValue();
				}
			}
		}
		return params;
	}
	
	
	
	public void insertSmartApSelectionTextParams(SmartApSelectionTextParams params){

		Map<String, Object> parametrers = new HashMap<String, Object>();

		parametrers.put("SMARTAP_TEXT_PARAMS", SMARTAP_TEXT_PARAMS);

		storageSourceService.insertRow(SMARTAP_TEXT_PARAMS, parametrers);	
	}
}
