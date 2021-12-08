using System.Net;
using System.Collections;
using System.Collections.Generic;
using Multimorphic.P3App.GUI;
using UnityEngine;
using UnityEngine.Networking;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Text;

/* 
    Initial version Copyright (c) 2021
    Author: Nicholas Baldridge
    Date: 2021-12-08
    This file is part of p3-scorbit-integration-public, which is released under the LGPL-2.1-only
    And is available on github.com as of the time of release
    See LICENSE or go to https://opensource.org/licenses/LGPL-2.1 for full license details
*/


public class ScorbitGUIOperations : P3Aware {

	protected string stoken;

	// Use this for initialization
	public override void Start () {
		base.Start();
	}
	
	protected override void CreateEventHandlers() {
		base.CreateEventHandlers();
		AddModeEventHandler("Evt_ScorbitAuth", ScorbitAuthEventHandler);
		AddModeEventHandler("Evt_ScorbitHeartbeat", ScorbitHeartbeatEventHandler);
		AddModeEventHandler("Evt_ScorbitEntryPost", ScorbitEntryEventHandler);
		AddModeEventHandler("Evt_ScorbitSessionLogPost", ScorbitSessionLogEventHandler);
	}

	public void ScorbitAuthEventHandler(string evtName, object evtData) {
		List<string> authInfo = (List<string>)evtData;
		StartCoroutine(ScorbitAuth(authInfo));
	}

	IEnumerator ScorbitAuth(List<string> authInfo) {
		string url = authInfo[0];
		string postData = authInfo[1];
		var client = UnityWebRequest.Post(url, postData);
		byte[] jsonToSend = new System.Text.UTF8Encoding().GetBytes(postData);
		client.uploadHandler = (UploadHandler)new UploadHandlerRaw(jsonToSend);
		client.downloadHandler = (DownloadHandler)new DownloadHandlerBuffer();
        
		client.SetRequestHeader("Content-Type", "application/json");
		client.SetRequestHeader("cache-control", "no-cache");

		yield return client.Send();

		if (client.isError)
		{
			Multimorphic.NetProcMachine.Logging.Logger.LogError("Scorbit Auth - Error While Sending: " + client.error);
		}
		else
		{
			JObject obj = JObject.Parse(client.downloadHandler.text);
			stoken = (string) obj["stoken"];
			//Multimorphic.NetProcMachine.Logging.Logger.LogError("Received: " + client.downloadHandler.text);
			PostGUIEventToModes("Evt_ScorbitSuccessfullyAuthenticated", stoken);
		}
	}

	public void ScorbitHeartbeatEventHandler(string evtName, object evtData) {
		List<string> heartbeatInfo = (List<string>)evtData;
		StartCoroutine(ScorbitHeartbeat(heartbeatInfo));
	}

	IEnumerator ScorbitHeartbeat(List<string> heartbeatInfo) {
		stoken = heartbeatInfo[0];
		string url = heartbeatInfo[1];
		
		var client = UnityWebRequest.Get(url);
		client.downloadHandler = (DownloadHandler)new DownloadHandlerBuffer();
		
		client.SetRequestHeader("Content-Type", "application/json");
		client.SetRequestHeader("cache-control", "no-cache");
		client.SetRequestHeader("Authorization", "SToken " + stoken);

		yield return client.Send();

		//Multimorphic.NetProcMachine.Logging.Logger.LogError("Response: " + client.downloadHandler.text);
		var response = client.downloadHandler.text;
		if (response.Contains("errors")) {
			PostGUIEventToModes("Evt_ScorbitHeartbeatError", response);
			PostGUIEventToModes("Evt_ScorbitNewAuth", true);
		} else {
			if (!response.Contains("machine_id")) {
				PostGUIEventToModes("Evt_ScorbitHeartbeatNotConnected", response);
			}
		}
	}

	public void ScorbitEntryEventHandler(string evtName, object evtData) {
		List<string> entryInfo = (List<string>)evtData;
		StartCoroutine(ScorbitEntry(entryInfo));
	}

	IEnumerator ScorbitEntry(List<string> entryInfo) {
		stoken = entryInfo[0];
		string url = entryInfo[1];
		string postData = entryInfo[2];
		string active = entryInfo[3];
		var client = UnityWebRequest.Post(url, postData);
		byte[] jsonToSend = new System.Text.UTF8Encoding().GetBytes(postData);
		client.uploadHandler = (UploadHandler)new UploadHandlerRaw(jsonToSend);
		client.downloadHandler = (DownloadHandler)new DownloadHandlerBuffer();


		client.SetRequestHeader("Content-Type", "application/json");
		client.SetRequestHeader("cache-control", "no-cache");
		client.SetRequestHeader("Authorization", "SToken " + stoken);

		yield return client.Send();

		if (client.isError)
		{
			Multimorphic.NetProcMachine.Logging.Logger.LogError("Scorbit Auth - Error While Sending: " + client.error);
			PostGUIEventToModes("Evt_ScorbitNewAuth", true);
		}
		else
		{
			JObject obj = JObject.Parse(client.downloadHandler.text);
			//Multimorphic.NetProcMachine.Logging.Logger.LogError("Received: " + client.downloadHandler.text);
			if (active == "true") {
				PostGUIEventToModes("Evt_ScorbitEntry", true);
			} else {
				PostGUIEventToModes("Evt_ScorbitEntry", false);
			}
		}
	}

	public void ScorbitSessionLogEventHandler(string evtName, object evtData) {
		List<string> sessionInfo = (List<string>)evtData;
		StartCoroutine(ScorbitSession(sessionInfo));
	}

	IEnumerator ScorbitSession(List<string> sessionInfo) {
		string url = sessionInfo[0];
		string postData = sessionInfo[1];

		var client = UnityWebRequest.Post(url, postData);
		client.SetRequestHeader("content-type", "application/json; charset=utf-8;");
		client.SetRequestHeader("cache-control", "no-cache");

		yield return client.Send();

		var response = client.downloadHandler.text;
		JObject sessionData = JObject.Parse(response);
		PostGUIEventToModes("Evt_ScorbitSessionLogResponse", sessionData);
	}

	// Update is called once per frame
	public override void Update () {
		base.Update();
	}
}
