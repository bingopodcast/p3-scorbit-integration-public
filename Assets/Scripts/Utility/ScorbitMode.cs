using System.Runtime.CompilerServices;
using System.Security.AccessControl;
using System.Threading;
using System.Net.Mime;
using System.Text.RegularExpressions;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Linq;
using System.Text;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Collections.Specialized;
using Multimorphic.NetProcMachine.Machine;
using Multimorphic.P3;
using Multimorphic.P3App.Modes;
using Multimorphic.NetProcMachine.Logging;
using Multimorphic.P3SA.Modes;
using Multimorphic.P3App.Modes.Data;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;
using UnityEngine.SocialPlatforms.Impl;
using Multimorphic.P3App.GUI;

/* 
    Initial version Copyright (c) 2021
    Author: Nicholas Baldridge
    Date: 2021-12-08
    This file is part of p3-scorbit-integration-public, which is released under the LGPL-2.1-only
    And is available on github.com as of the time of release
    See LICENSE or go to https://opensource.org/licenses/LGPL-2.1 for full license details
*/


namespace Multimorphic.P3SA.Modes
{

	/// <summary>
	/// A mode that connects to Scorebit for API features.
	/// </summary>
    public class ScorbitMode : P3Mode
	{
        // This must be set so that the url makes the appropriate call.  See the event handler for "ScorbitProduction".
        private bool production;
        private string endpoint = "";
        // This is used for the "entry" service, and needs to be generated on mode start.
        private Guid sessionUUID;
        // The "entry" service doesn't keep track of state, relying upon the app to do
        // it for it.  Aside from whether the game is active or not, the game must
        // send a sequence ID.
        private int sessionSequence;

        // The auth token will be sent back once a session has been authenticated.
        // It is invalidated on an unknown timetable.
        private string stoken;

        // Scorbit requires the session time also be tracked, along with a sequence.
        // The one could infer the other, but this is a requirement, therefore, we
        // need something to update on a deltaTime basis.  Rather than use ticks,
        // just add a method to update from the GUI scriptlet.
        private float sessionTime;

        // This is set on a per-app basis
        private string appUUID;

        // This is set on a per-app basis
        private string appPEM;
        
		public ScorbitMode (P3Controller controller, int priority)
			: base(controller, priority)
		{
        }

 		public override void mode_started ()
		{
			base.mode_started ();

            // A GUI component needs to load before the game will be able to use Scorbit fully.  Wait to
            // call the initial authentication until receiving the go-ahead from the Attract mode.
            AddGUIEventHandler("Evt_StartScorbit", StartScorbitEventHandler);

            // Set the per-app UUID
            AddModeEventHandler("Evt_ScorbitUUID", ScorbitUUIDEventHandler, Priority);

            // Set the PEM for crypto operations per-app
            AddModeEventHandler("Evt_ScorbitPEM", ScorbitPemEventHandler, Priority);

            // Successful authentication will send a signal to start heartbeats (or continue if re-auth).
            AddGUIEventHandler("Evt_ScorbitSuccessfullyAuthenticated", ScorbitSuccessfullyAuthenticatedEventHandler);
            
            AddModeEventHandler("Evt_ScorbitEntry", ScorbitEntryEventHandler, Priority);
            AddModeEventHandler("Evt_ScorbitProduction", ScorbitProductionEventHandler, Priority);
            AddGUIEventHandler("Evt_ScorbitEntryRepost", ScorbitEntryRepostEventHandler);
            AddGUIEventHandler("Evt_ScorbitUpdateSessionTime", ScorbitUpdateSessionTimeEventHandler);
            
            production = false;

            // Based on the production boolean, ensure that the endpoint is set correctly.
            if (production == false) {
                endpoint = "https://scorbit-api-staging.herokuapp.com";
            } else {
                endpoint = "https://api.scorbit.io";
            }
            sessionUUID = Guid.NewGuid();
            sessionSequence = 0;
		}

 		public override void mode_stopped ()
		{
			base.mode_stopped ();
            ScorbitEntry(false);
		}

        private byte[] MD5Converter(string item)
        {
            // Calculate and return an MD5Sum based on string input.
            byte[] tmp;
            byte[] hash;
            tmp = ASCIIEncoding.ASCII.GetBytes(item);
            hash = new MD5CryptoServiceProvider().ComputeHash(tmp);
            
            return hash;
        }

        private byte[] Combine(params byte[][] arrays)
        {
            byte[] rv = new byte[arrays.Sum(a => a.Length)];
            int offset = 0;
            foreach (byte[] array in arrays) {
                System.Buffer.BlockCopy(array, 0, rv, offset, array.Length);
                offset += array.Length;
            }
            return rv;
        }

        public bool ScorbitProductionEventHandler(string evtName, object evtData) {
            production = true;
            endpoint = "https://api.scorbit.io";
            return true;
        }

        public void StartScorbitEventHandler(string evtName, object evtData)
        {
            // The UUID is one component that must be pre-generated on a per-app basis.  
            // You only need to do this once per app.  You can generate this online 
            // or via code.  In C#, one way to do this is via Guid myuuid = Guid.NewGuid();
            // Remove the dashes in the generated number, and store it here.
            // We ALSO need the UUID with dashes to present the QR code to associate the app.
            string uuid = appUUID;
            
            byte[] uuidHex = HexStringConverter.ToByteArray(uuid);
            
            // The Serial number is a long converted to string.  The MachineID is alphanumeric.
            // Note that the Machine Id will not pull properly within the Unity simulator.
            if (production == true) {
                string serial = data.GetGameAttributeValue("Machine Id").ToString();
            } else {
                string serial = "0123-4567-890A-BCDE";
            }
            //Logger.LogError(("ScorbitMode: Machine ID " + serial.ToString()));

            string convertedSerial = "";
            // Convert machine serial to integer for passing to service.
            if (serial != null) {
                var md5 = MD5Converter(serial);
                convertedSerial = BitConverter.ToInt32(md5, 0).ToString();

                Logger.LogError("ScorbitMode: Serial " + convertedSerial);
            } else {
                Logger.LogError("Serial number could not be determined.  Ensure Settings/Info/Machine ID is populated.");
            }

            // Determine network time and convert to Unix time prior to each request.
            var networkTime = GetNetworkTime();
            var unixTime = GetUnixTime(networkTime).ToString();
            Logger.LogError("ScorbitMode: Time " + unixTime);


            // The private and public keys need to be generated by the programmer.  These are not to be
            // distributed.  To generate the keys needed, a computer with OpenSSL is likely easiest.
            //Generate private key:
            //$ openssl ecparam -name prime256v1 -genkey -noout -out private.pem
            
            // Your PEM should be available here - ensure that it includes the header and footer "BEGIN EC PRIVATE KEY"
            // and "END EC PRIVATE KEY".  This is used to derive the public key.  Also note that you need
            // to paste as a single line, with '\n' newline characters between the BEGIN and END declaration:
            string pem = appPEM;

            // The public and private key -must- be generated separately for each application.
            // The public key (and -only- the public key) should be provided to Spinner Systems to allow you to authenticate.
            // See documentation for details.

            var uuidByte = uuidHex;
            var timestampByte = Encoding.ASCII.GetBytes(unixTime);
            var data = Combine(uuidByte, timestampByte);
            
            var keyPair = GetKeyPair(pem);
            
            // Get the public key in DER format for use in requests.
            byte[] hexPublicKeyArray = Org.BouncyCastle.X509.SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetDerEncoded();
            string publicKeyBase64 = Convert.ToBase64String(hexPublicKeyArray);
            var hexPublicKey = BitConverter.ToString(hexPublicKeyArray);
            hexPublicKey = hexPublicKey.Replace("-", "").Remove(0,54);
            var signature = SignData(data, keyPair.Private);
            var signatureString = BitConverter.ToString(signature).Replace("-", "");

            // When production is false, test the private and public keys and Log information about a simple signing.
            // This method will display the keys used in the Unity log for simple troubleshooting.  It should NEVER
            // be used to display the keys 
            if (production == false) {
                var valid = VerifySignature(data, signature, keyPair.Public);
                Logger.LogError("VERIFYING: " + valid.ToString());
            }

            // Using POST <base_url>/api/stoken/ pass 5 parameters: provider, uuid, serial_number, timestamp and sign in a json-encoded format:
            // provider=manufacturer_name&uuid=UUID&serial_number=NUMERICSERIAL&timestamp=UNIXNTPTIMESTAMP&sign=SIGNATURESTRING
            // This is used for each transaction to get a token.
            var url = endpoint + "/api/stoken/";

            var postJSON = new JObject();
            postJSON.Add("provider", "multimorphic");
            postJSON.Add("uuid", uuid);
            postJSON.Add("serial_number", convertedSerial);
            postJSON.Add("timestamp", unixTime);
            postJSON.Add("sign", signatureString.ToLower());
            
            var postData = JsonConvert.SerializeObject(postJSON);
            //Logger.LogError("ScorbitMode: Posted to " + url + postData.ToString());
            List<string> auth = new List<string>();
            auth.Add(url);
            auth.Add(postData);
            PostModeEventToGUI("Evt_ScorbitAuth", auth);
            // The GUI needs to present a QR code in the feature menu using the following syntax
            // of course the UUID must be in actual UUID format:
            // https://scorbit.link/qrcode?$deeplink_path=MANUFACTURER&machineid=1234&uuid=UUID
            // Please contact support@scorbit.io for details.
        }

        static class HexStringConverter
        {
            public static byte[] ToByteArray(String HexString)
            {
                int NumberChars = HexString.Length;
                byte[] bytes = new byte[NumberChars / 2];
                for (int i = 0; i < NumberChars; i += 2)
                {
                    bytes[i / 2] = Convert.ToByte(HexString.Substring(i, 2), 16);
                }
                return bytes;
            }
        }

        private AsymmetricCipherKeyPair GetKeyPair(string pem)
        {
            PemReader pr = new PemReader(new StringReader(pem));
            AsymmetricCipherKeyPair keyPair = (AsymmetricCipherKeyPair)pr.ReadObject();
            ECPrivateKeyParameters privateKeyParams = (ECPrivateKeyParameters)keyPair.Private;
            ECPublicKeyParameters publicKeyParams = (ECPublicKeyParameters)keyPair.Public;
            
            return new AsymmetricCipherKeyPair(publicKeyParams, privateKeyParams);
        }

        private byte[] SignData(byte[] data, AsymmetricKeyParameter privateKey)
        {
            var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
            signer.Init(true, privateKey);
            signer.BlockUpdate(data, 0, data.Length);

            return signer.GenerateSignature();
        }

        public bool VerifySignature(byte[] data, byte[] signature, AsymmetricKeyParameter publicKey)
        {
            var verifier = SignerUtilities.GetSigner("SHA-256withECDSA");
            verifier.Init(false, publicKey);
            verifier.BlockUpdate(data, 0, data.Length);

            return verifier.VerifySignature(signature);
        }

        public static DateTime GetNetworkTime()
        {
            // Pulls time from the nearest NTP server
            const string ntpServer = "pool.ntp.org";
            var ntpData = new byte[48];
            ntpData[0] = 0x1B; //LeapIndicator = 0 (no warning), VersionNum = 3 (IPv4 only), Mode = 3 (Client Mode)

            var addresses = Dns.GetHostEntry(ntpServer).AddressList;
            var ipEndPoint = new IPEndPoint(addresses[0], 123);
            var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            socket.Connect(ipEndPoint);
            socket.Send(ntpData);
            socket.Receive(ntpData);
            socket.Close();

            ulong intPart = (ulong)ntpData[40] << 24 | (ulong)ntpData[41] << 16 | (ulong)ntpData[42] << 8 | (ulong)ntpData[43];
            ulong fractPart = (ulong)ntpData[44] << 24 | (ulong)ntpData[45] << 16 | (ulong)ntpData[46] << 8 | (ulong)ntpData[47];

            var milliseconds = (intPart * 1000) + ((fractPart * 1000) / 0x100000000L);
            var networkDateTime = (new DateTime(1900, 1, 1)).AddMilliseconds((long)milliseconds);

            return networkDateTime;
        }

        public static int GetUnixTime(DateTime currentTime) {
            return (Int32)(currentTime.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
        }

        public void ScorbitSuccessfullyAuthenticatedEventHandler(string evtName, object evtData) {
            stoken = evtData.ToString();
            Heartbeat();
        }

        public void Heartbeat() {
            this.cancel_delayed("heartbeat");
            List<string> heartbeat = new List<string>();
            var url = endpoint + "/api/heartbeat/";
            heartbeat.Add(stoken);
            heartbeat.Add(url);
            PostModeEventToGUI("Evt_ScorbitHeartbeat", heartbeat);
			delay("heartbeat", Multimorphic.NetProc.EventType.None, 10, new Multimorphic.P3.VoidDelegateNoArgs (Heartbeat));
        }

        public bool ScorbitEntryEventHandler(string evtName, object evtData) {
            ScorbitEntry((bool) evtData);
            return true;
        }

        public void ScorbitEntryRepostEventHandler(string evtName, object evtData) {
            ScorbitEntry(true);
        }

        public void ScorbitEntry(bool active) {
            // Scorbit keeps track of the entries by checking the Session sequence
            // increment this once per loop while the game is active.
            sessionSequence += 1;

            var url = endpoint + "/api/entry/";
            var postJSON = new JObject();
            postJSON.Add("session_uuid", sessionUUID.ToString());
            postJSON.Add("session_sequence", sessionSequence);
            postJSON.Add("session_time", (int)sessionTime);
            postJSON.Add("active", active);
            postJSON.Add("current_player", data.currentPlayerIndex + 1);
            postJSON.Add("current_ball", data.ball);
            for (int i=1; i <= 6; i++) {
                if (data.Players.Count >= i) {
                    postJSON.Add("current_p" + i + "_score", data.Players[i-1].GetScore());
                } else {
                    postJSON.Add("current_p" + i + "_score", -1);
                }
                // Service supports a maximum of 6 players.
                if (i == 6) {
                    break;
                }
            }

            // ScorbitModes must be added to data.currentPlayer in order to post within the app.
            // Scorbit contains syntax in the following style - see:
            // https://github.com/scorbit-io/scorbit_api_doc/wiki/08.-Game-Modes
            // ex: <CA><n>{<color>}:<Display text>
            // where CA = two letter Category, color = color name, like "yellow", and 
            // Display text is the mode name.
            // This key should contain an ever-expanding string value with the list of modes started.
            // Scorbit doesn't properly discard empty game_modes.  We need to build protection.
            if (data.currentPlayer.GetData("ScorbitModes", "") != "") {
                postJSON.Add("game_modes", data.currentPlayer.GetData("ScorbitModes", ""));
            }
            var postData = JsonConvert.SerializeObject(postJSON);
            //Logger.LogError(postData);
            List<string> entry = new List<string>();
            entry.Add(stoken);
            entry.Add(url);
            entry.Add(postData);
            entry.Add(active.ToString());

            PostModeEventToGUI("Evt_ScorbitEntryPost", entry);
        }

        public void ScorbitUpdateSessionTimeEventHandler(string evtName, object evtData) {
            sessionTime += (float)evtData;
        }

        public bool ScorbitUUIDEventHandler(string evtName, object evtData) {
            appUUID = evtData.ToString();
            return true;
        }

        public bool ScorbitPemEventHandler(string evtName, object evtData) {
            appPEM = evtData.ToString();
            return true;
        }
	}
}
