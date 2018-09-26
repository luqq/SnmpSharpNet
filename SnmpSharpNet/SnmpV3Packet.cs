// This file is part of SNMP#NET.
// 
// SNMP#NET is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// SNMP#NET is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with SNMP#NET.  If not, see <http://www.gnu.org/licenses/>.
// 
using System;

namespace SnmpSharpNet
{
    /// <summary>
    /// SNMP version 3 packet implementation class.
    /// </summary>
    /// 
    /// <remarks>
    /// Available packet classes are:
    /// <ul>
    /// <li><see cref="SnmpV1Packet"/></li>
    /// <li><see cref="SnmpV1TrapPacket"/></li>
    /// <li><see cref="SnmpV2Packet"/></li>
    /// <li><see cref="SnmpV3Packet"/></li>
    /// </ul>
    /// 
    /// This class is provided to simplify encoding and decoding of packets and to provide consistent interface
    /// for users who wish to handle transport part of protocol on their own without using the <see cref="UdpTarget"/> 
    /// class.
    /// 
    /// <see cref="SnmpPacket"/> and derived classes have been developed to implement SNMP version 1, 2 and 3 packet 
    /// support. 
    /// 
    /// For SNMP version 1 and 2 packet, <see cref="SnmpV1Packet"/> and <see cref="SnmpV2Packet"/> classes 
    /// provide sufficient support for encoding and decoding data to/from BER buffers to satisfy requirements 
    /// of most applications. 
    /// 
    /// SNMP version 3 on the other hand requires a lot more information to be passed to the encoder method and 
    /// returned by the decode method. While using SnmpV3Packet class for full packet handling is possible, transport
    /// specific class <see cref="UdpTarget"/> uses <see cref="SecureAgentParameters"/> class to store protocol
    /// version 3 specific information that carries over from request to request when used on the same SNMP agent
    /// and therefore simplifies both initial definition of agents configuration (mostly security) as well as
    /// removes the need for repeated initialization of the packet class for subsequent requests.
    /// 
    /// If you decide not to use transport helper class(es) like <see cref="UdpTarget"/>, BER encoding and
    /// decoding and packets is easily done with SnmpPacket derived classes.
    /// 
    /// Example, SNMP version 1 packet encoding:
    /// <code>
    /// SnmpV1Packet packetv1 = new SnmpV1Packet();
    /// packetv1.Community.Set("public");
    /// packetv1.Pdu.Set(mypdu);
    /// byte[] berpacket = packetv1.encode();
    /// </code>
    /// 
    /// Example, SNMP version 3 noAuthNoPriv encoding:
    /// <code>
    /// SnmpV3Packet packetv3 = new SnmpV3Packet();
    /// packetv3.noAuthNoPriv("myusername");
    /// packetv3.SetEngineTime(engineTime, engineBoots); // See SNMPv3 discovery process for details
    /// packetv3.SetEngineId(engineId); // See SNMPv3 discovery process for details
    /// packetv3.IsReportable = true;
    /// packetv3.Pdu.Set(mypdu);
    /// byte[] berpacket = packetv3.encode();
    /// </code>
    ///
    /// Example, SNMP version 3 authNoPriv using MD5 authentication packet encoding:
    /// <code>
    /// SnmpV3Packet packetv3 = new SnmpV3Packet();
    /// packetv3.authNoPriv("myusername", "myAuthenticationPassword", AuthenticationDigests.MD5);
    /// packetv3.SetEngineTime(engineTime, engineBoots); // See SNMPv3 discovery process for details
    /// packetv3.SetEngineId(engineId); // See SNMPv3 discovery process for details
    /// packetv3.IsReportable = true;
    /// packetv3.Pdu.Set(mypdu);
    /// byte[] berpacket = packetv3.encode();
    /// </code>
    ///
    /// Example, SNMP version 3 authPriv using MD5 authentication and DES encryption packet encoding:
    /// <code>
    /// SnmpV3Packet packetv3 = new SnmpV3Packet();
    /// packetv3.authPriv("myusername", "myAuthenticationPassword", AuthenticationDigests.MD5,
    ///		"myPrivacyPassword", PrivacyProtocols.DES);
    /// packetv3.SetEngineTime(engineTime, engineBoots); // See SNMPv3 discovery process for details
    /// packetv3.SetEngineId(engineId); // See SNMPv3 discovery process for details
    /// packetv3.IsReportable = true;
    /// packetv3.Pdu.Set(mypdu);
    /// byte[] berpacket = packetv3.encode();
    /// </code>
    /// 
    /// When decoding SNMP version 3 packets, SnmpV3Packet class needs to be initialized with the same values
    /// security values as a request does. This includes, authoritative engine id, engine boots and engine time,
    /// if authentication is used, authentication digest and password and for encryption, password and privacy
    /// protocol used. Without these parameters packet class will not be able to verify the incoming packet and
    /// responses will be discarded even if they are valid.
    /// </remarks>
    public class SnmpV3Packet: SnmpPacket
    {
        /// <summary>
        /// SNMP version 3 message id. Uniquly identifies the message.
        /// </summary>
        private Integer32 _messageId;
        /// <summary>
        /// Get SNMP version 3 message id object.
        /// </summary>
        public Int32 MessageId
        {
            get 
            {
                return _messageId.Value; 
            }
            set
            {
                _messageId.Value = value;
            }
        }

        /// <summary>
        /// Maximum message size. In the discovery packet, set it to the maximum acceptable size = 64KB. Agent will
        /// return the maximum value it is ready to handle so you should stick with that value in all following
        /// requests.
        /// </summary>
        private Integer32 _maxMessageSize;

        /// <summary>
        /// Get maximum message size to be sent to the agent in the request.
        /// </summary>
        public Int32 MaxMessageSize
        {
            get { return _maxMessageSize.Value; }
            set { _maxMessageSize.Value = value; }
        }

        /// <summary>
        /// Message flags interface. Allows you to directly set or clear SNMP version 3 header flags field.
        /// 
        /// Available flags are MsgFlags.Authentication, MsgFlags.Privacy and MsgFlags.Reportable.
        /// 
        /// Please be careful how you use this property. After setting authentication or privacy parameters to true,
        /// you will need to update <see cref="UserSecurityModel"/> authentication and privacy types to the correct
        /// values otherwise encoding/decoding will not work.
        /// </summary>
        public MsgFlags MsgFlags { get; }

        /// <summary>
        /// Security model code. Only supported security model is UserSecurityModel (integer value 3)
        /// </summary>
        protected Integer32 _securityModel;

        /// <summary>
        /// Get <see cref="UserSecurityModel"/> class reference.
        /// </summary>
        public UserSecurityModel USM { get; }

        /// <summary>
        /// Override base class implementation. Returns class ScopedPdu cast as Pdu
        /// </summary>
        public override Pdu Pdu
        {
            get
            {
                return (Pdu)ScopedPdu;
            }
        }

        /// <summary>
        /// Access packet ScopedPdu class.
        /// </summary>
        public ScopedPdu ScopedPdu { get; }

        /// <summary>
        /// Standard constructor.
        /// </summary>
        public SnmpV3Packet()
            : base(SnmpVersion.Ver3)
        {
            _messageId = new Integer32();
            _maxMessageSize = new Integer32(64 * 1024);
            MsgFlags = new MsgFlags
            {
                Reportable = true // Make sure reportable is set to true by default
            };
            _securityModel = new Integer32();
            USM = new UserSecurityModel();
            ScopedPdu = new ScopedPdu();
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <remarks>
        /// Sets internal ScopedPdu class to the argument supplied instance of the
        /// class. This is a good cheat that will allow you direct access to the internal ScopedPdu class
        /// since it is not cloned but assigned to the internal variable.
        /// </remarks>
        /// <param name="pdu"><see cref="ScopedPdu"/> class assigned to the class</param>
        public SnmpV3Packet(ScopedPdu pdu)
            : this()
        {
            if( pdu != null )
            {
                ScopedPdu = pdu;
            }
        }

        /// <summary>
        /// Constructor.
        /// </summary>
        /// <remarks>
        /// Create new SNMPv3 packet class and initialize security parameters
        /// </remarks>
        /// <param name="param">Initialization SNMPv3 security parameters</param>
        public SnmpV3Packet(SecureAgentParameters param)
            : this()
        {
            if( param != null )
            {
                param.InitializePacket(this);
            }
        }

        /// <summary>
        /// Constructor
        /// </summary>
        /// <remarks>
        /// Create new SNMPv3 packet class and initialize security parameters and ScopedPdu.
        /// </remarks>
        /// <param name="param">SNMPv3 security parameters</param>
        /// <param name="pdu">ScopedPdu assigned to the class</param>
        public SnmpV3Packet(SecureAgentParameters param, ScopedPdu pdu)
            : this(param)
        {
            if( pdu != null )
            {
                ScopedPdu = pdu;
            }
        }

        /// <summary>
        /// Set class security to no authentication and no privacy. User name is set to "initial" (suitable for
        /// SNMP version 3 discovery process). Change username before using if discovery is not being performed.
        /// </summary>
        public void NoAuthNoPriv()
        {
            MsgFlags.Authentication = false;
            MsgFlags.Privacy = false;
            USM.SecurityName.Set("initial");
        }

        /// <summary>
        /// Set class security to no authentication and no privacy with the specific user name.
        /// </summary>
        /// <param name="userName">User name</param>
        public void NoAuthNoPriv(byte[] userName)
        {
            MsgFlags.Authentication = false;
            MsgFlags.Privacy = false;
            USM.SecurityName.Set(userName);
        }

        /// <summary>
        /// Set class security to enabled authentication and no privacy. To perform authentication,
        /// authentication password needs to be supplied and authentication protocol to be used
        /// to perform authentication.
        /// 
        /// This method does not initialize the packet user name. Use SNMPV3Packet.SecurityName
        /// method to set the security name (also called user name) for this request.
        /// </summary>
        /// <param name="userName">User name</param>
        /// <param name="authenticationPassword">Authentication password to use in authenticating the message. This
        /// value has to match the password configured on the agent.</param>
        /// <param name="authenticationProtocol">Authentication protocol to use. Available authentication protocols are:
        /// <see cref="AuthenticationDigests.MD5"/> for HMAC-MD5 authentication, and <see cref="AuthenticationDigests.SHA1"/>
        /// for HMAC-SHA1 message authentication.</param>
        public void AuthNoPriv(byte[] userName, byte[] authenticationPassword, AuthenticationDigests authenticationProtocol)
        {
            NoAuthNoPriv(userName); // reset authentication and privacy values and set user name
            MsgFlags.Authentication = true;
            USM.Authentication = authenticationProtocol;
            USM.AuthenticationSecret.Set(authenticationPassword);
            MsgFlags.Privacy = false;
        }

        /// <summary>
        /// Set packet security to authentication enabled and privacy protection enabled (SNMP v3 mode authPriv)
        /// </summary>
        /// <param name="userName">User name</param>
        /// <param name="authenticationPassword">Authentication password</param>
        /// <param name="authenticationProtocol">Authentication protocol. See definitions in <see cref="AuthenticationDigests"/> enumeration.</param>
        /// <param name="privacyPassword">Privacy protection password.</param>
        /// <param name="privacyProtocol">Privacy protocol. See definitions in <see cref="PrivacyProtocols"/> enumeration.</param>
        public void AuthPriv(byte[] userName, byte[] authenticationPassword, AuthenticationDigests authenticationProtocol, byte[] privacyPassword, PrivacyProtocols privacyProtocol)
        {
            NoAuthNoPriv(userName); // reset authentication and privacy values and set user name
            MsgFlags.Authentication = true;
            USM.AuthenticationSecret.Set(authenticationPassword);
            USM.Authentication = authenticationProtocol;
            MsgFlags.Privacy = true;
            USM.PrivacySecret.Set(privacyPassword);
            USM.Privacy = privacyProtocol;
        }

        /// <summary>
        /// Set engine time and boots values
        /// </summary>
        /// <param name="engineBoots">Authoritative engine boots value retrived from the agent during discovery procedure.</param>
        /// <param name="engineTime">Engine time value.</param>
        public void SetEngineTime(int engineBoots, int engineTime)
        {
            USM.EngineBoots = engineBoots;
            USM.EngineTime = engineTime;
        }

        /// <summary>
        /// Set authoritative engine id
        /// </summary>
        /// <param name="engineId">Authoritative engine id</param>
        public void SetEngineId(byte[] engineId)
        {
            USM.EngineId.Set(engineId);
        }

        /// <summary>
        /// Get or set SNMP version 3 packet Reportable flag in the message flags section. By default this value is set to true.
        /// </summary>
        public bool IsReportable
        {
            get
            {
                return MsgFlags.Reportable;
            }
            set
            {
                MsgFlags.Reportable = value;
            }
        }

        /// <summary>
        /// Packet is a discovery request
        /// </summary>
        /// <remarks>
        /// Class checks if Engine id, engine boots and engine time values are set to default values (null, 0 and 0). If they are
        /// packet is probably a discovery packet, otherwise it is not an false is returned
        /// </remarks>
        public bool IsDiscoveryPacket
        {
            get
            {
                if( USM.EngineId.Length == 0 && USM.EngineTime == 0 && USM.EngineBoots == 0)
                {
                    return true;
                }

                return false;
            }
        }

        #region Encode & decode

        /// <summary>
        /// "Look-ahead" decode of SNMP packet header including USM information
        /// </summary>
        /// <remarks>
        /// Decode first component of the SNMP version 3 packet allowing the caller to retrieve USM SecureName needed to retrieve
        /// client security parameters that will allow authentication and privacy decryption to take place.
        /// 
        /// This method is used to support Agent like behavior or to handle unsolicited packets like TRAP and INFORMs. In all of
        /// these cases, sender of packets will forward a packet without a request being sent by you. In turn, you will need
        /// to parse enough of the packet to retrieve SecureName which you can use to retrieve security parameters associated with
        /// that user and attempt to authorize and privacy decrypt the received packet.
        /// 
        /// Only use this method when your application is acting as an Agent or if you need to process TRAP and INFORM packets.
        /// </remarks>
        /// <param name="berBuffer">Raw SNMP version 3 packet</param>
        /// <param name="length">SNMP version 3 packet length</param>
        /// <returns>UserSecurityModel class parsed from the parameter SNMP version 3 packet</returns>
        /// <exception cref="SnmpInvalidVersionException">Thrown when attempting to parse an SNMP packet that is not version 3</exception>
        /// <exception cref="OverflowException">Thrown when header specifies packet length that is longer then the amount of data received.</exception>
        /// <exception cref="SnmpDecodingException">Thrown when invalid sequence is enountered while decoding global message data sequence</exception>
        /// <exception cref="SnmpException">Thrown with SnmpException.UnsupportedNoAuthPriv when packet is using privacy without authentication (not allowed)</exception>
        /// <exception cref="SnmpException">Thrown with SnmpException.UnsupportedSecurityModel when packet is sent with security model other then USM (only USM is defined in SNMPv3 standard)</exception>
        public UserSecurityModel GetUSM(byte[] berBuffer, int length)
        {
            MutableByte buffer = new MutableByte(berBuffer, length);

            int offset = 0;

            // let base class parse first sequence and SNMP version number
            offset = base.Decode(buffer, length);

            // check for correct SNMP protocol version
            if (_protocolVersion != (int) SnmpVersion.Ver3)
            {
                throw new SnmpInvalidVersionException("Expecting SNMP version 3.");
            }

            // now grab the global message data sequence header information
            byte asnType = AsnType.ParseHeader(buffer, ref offset, out int len);

            if ( asnType != SnmpConstants.SMI_SEQUENCE )
            {
                throw new SnmpDecodingException("Invalid sequence type when decoding global message data sequence.");
            }

            // check that packet size can accommodate the length specified in the header
            if (len > (buffer.Length - offset))
            {
                throw new OverflowException("Packet is too small to contain the data described in the header.");
            }

            // retrieve message id
            offset = _messageId.Decode(buffer, offset);

            // max message size
            offset = _maxMessageSize.Decode(buffer, offset);

            // message flags
            offset = MsgFlags.Decode(buffer, offset);

            // verify that a valid authentication/privacy configuration is present in the packet
            if (MsgFlags.Authentication == false && MsgFlags.Privacy == true)
            {
                throw new SnmpException(SnmpException.UnsupportedNoAuthPriv,
                                        "SNMP version 3 noAuthPriv security combination is not supported.");
            }

            // security model code
            offset = _securityModel.Decode(buffer, offset);

            // we only support USM. code = 0x03
            if (_securityModel.Value != USM.Type)
            {
                throw new SnmpException(SnmpException.UnsupportedSecurityModel,
                                        "Class only support SNMP Version 3 User Security Model.");
            }

            // parse user security model
            offset = USM.Decode(buffer, offset);

            return USM;
        }

        /// <summary>
        /// Decode SNMP version 3 packet. This method will perform authentication check and decode privacy protected <see cref="ScopedPdu"/>. This method will
        /// not check for the timeliness of the packet, correct engine boot value or engine id because it does not have a reference to the engine time prior to this call.
        /// </summary>
        /// <param name="berBuffer">BER encoded SNMP version 3 packet buffer</param>
        /// <param name="length">Buffer length</param>
        public override int Decode(byte[] berBuffer, int length)
        {
            byte[] pkey = null;
            byte[] akey = null;
            if (MsgFlags.Authentication && USM.EngineId.Length > 0)
            {
                IAuthenticationDigest auth = Authentication.GetInstance(USM.Authentication);
                if (auth == null)
                {
                    throw new SnmpException(SnmpException.UnsupportedNoAuthPriv, "Invalid authentication protocol.");
                }

                akey = auth.PasswordToKey(USM.AuthenticationSecret, USM.EngineId);
                if (MsgFlags.Privacy && USM.EngineId.Length > 0)
                {
                    IPrivacyProtocol privacyProtocol = PrivacyProtocol.GetInstance(USM.Privacy);
                    if (privacyProtocol == null)
                    {
                        throw new SnmpException(SnmpException.UnsupportedPrivacyProtocol, "Specified privacy protocol is not supported.");
                    }

                    pkey = privacyProtocol.PasswordToKey(USM.PrivacySecret, USM.EngineId, auth);
                }
            }
            return Decode(berBuffer, length, akey, pkey);
        }

        /// <summary>
        /// Decode SNMP version 3 packet. This method will perform authentication check and decode privacy protected <see cref="ScopedPdu"/>. This method will
        /// not check for the timeliness of the packet, correct engine boot value or engine id because it does not have a reference to the engine time prior to this call.
        /// </summary>
        /// <param name="berBuffer">BER encoded SNMP version 3 packet buffer</param>
        /// <param name="length">Buffer length</param>
        /// <param name="authKey">Authentication key (not password)</param>
        /// <param name="privKey">Privacy key (not password)</param>
        public int Decode(byte[] berBuffer, int length, byte[] authKey, byte[] privKey)
        {
            MutableByte buffer = new MutableByte(berBuffer, length);

            int offset = 0;

            // let base class parse first sequence and SNMP version number
            offset = base.Decode(buffer, length);

            // check for correct SNMP protocol version
            if (_protocolVersion != (int)SnmpVersion.Ver3)
            {
                throw new SnmpInvalidVersionException("Expecting SNMP version 3.");
            }

            // now grab the global message data sequence header information
            byte asnType = AsnType.ParseHeader(buffer, ref offset, out int len);
            if (asnType != SnmpConstants.SMI_SEQUENCE)
            {
                throw new SnmpDecodingException("Invalid sequence type in global message data sequence.");
            }

            // check that packet size can accommodate the length specified in the header
            if (len > (buffer.Length - offset))
            {
                throw new OverflowException("Packet is too small to contain the data described in the header.");
            }

            // retrieve message id
            offset = _messageId.Decode(buffer, offset);

            // max message size
            offset = _maxMessageSize.Decode(buffer, offset);

            // message flags
            offset = MsgFlags.Decode(buffer, offset);

            // verify that a valid authentication/privacy configuration is present in the packet
            if (MsgFlags.Authentication == false && MsgFlags.Privacy == true)
            {
                throw new SnmpException(SnmpException.UnsupportedNoAuthPriv, "SNMP version 3 noAuthPriv security combination is not supported.");
            }

            // security model code
            offset = _securityModel.Decode(buffer, offset);

            // we only support USM. code = 0x03
            if (_securityModel.Value != USM.Type)
            {
                throw new SnmpException(SnmpException.UnsupportedSecurityModel, "Class only support SNMP Version 3 User Security Model.");
            }

            // parse user security model
            offset = USM.Decode(buffer, offset);

            // Authenticate message if authentication flag is set and packet is not a discovery packet
            if (MsgFlags.Authentication && USM.EngineId.Length > 0)
            {
                // Authenticate packet
                if (USM.AuthenticationParameters.Length != 12)
                {
                    throw new SnmpAuthenticationException("Invalid authentication parameter field length.");
                }

                if (!USM.IsAuthentic(authKey, buffer))
                {
                    throw new SnmpAuthenticationException("Authentication of the incoming packet failed.");
                }
            }

            // Decode ScopedPdu if it is privacy protected and packet is not a discovery packet
            if (MsgFlags.Privacy && USM.EngineId.Length > 0)
            {
                IPrivacyProtocol privacyProtocol = PrivacyProtocol.GetInstance(USM.Privacy);
                if (privacyProtocol == null)
                {
                    throw new SnmpException(SnmpException.UnsupportedPrivacyProtocol, "Privacy protocol requested is not supported.");
                }
                if (USM.PrivacyParameters.Length != privacyProtocol.PrivacyParametersLength)
                {
                    throw new SnmpException(SnmpException.InvalidPrivacyParameterLength, "Invalid privacy parameters field length.");
                }

                // Initialize a temporary OctetString class to hold encrypted ScopedPdu
                OctetString encryptedScopedPdu = new OctetString();
                offset = encryptedScopedPdu.Decode(buffer, offset);

                // decode encrypted packet
                byte[] decryptedScopedPdu = privacyProtocol.Decrypt(encryptedScopedPdu, 0, encryptedScopedPdu.Length, privKey, USM.EngineBoots, USM.EngineTime, USM.PrivacyParameters);
                int tempOffset = 0;
                offset = ScopedPdu.Decode(decryptedScopedPdu, tempOffset);
            }
            else
            {
                offset = ScopedPdu.Decode(buffer, offset);
            }

            return offset;
        }
    
        /// <summary>
        /// Encode SNMP version 3 packet
        /// </summary>
        /// <remarks>
        /// Before encoding the packet into a byte array you need to ensure all required information is
        /// set. Examples of required information is request type, Vbs (Oid + values pairs), USM settings including
        /// SecretName, authentication method and secret (if needed), privacy method and secret (if needed), etc.
        /// </remarks>
        /// <returns>Byte array BER encoded SNMP packet.</returns>
        public override byte[] Encode()
        {
            byte[] pkey = null;
            byte[] akey = null;
            if (MsgFlags.Authentication && USM.EngineId.Length > 0)
            {
                IAuthenticationDigest auth = Authentication.GetInstance(USM.Authentication);
                if (auth == null)
                {
                    throw new SnmpException(SnmpException.UnsupportedNoAuthPriv, "Invalid authentication protocol.");
                }

                akey = auth.PasswordToKey(USM.AuthenticationSecret, USM.EngineId);
                if (MsgFlags.Privacy && USM.EngineId.Length > 0)
                {
                    IPrivacyProtocol privacyProtocol = PrivacyProtocol.GetInstance(USM.Privacy);
                    if (privacyProtocol == null)
                    {
                        throw new SnmpException(SnmpException.UnsupportedPrivacyProtocol, "Specified privacy protocol is not supported.");
                    }

                    pkey = privacyProtocol.PasswordToKey(USM.PrivacySecret, USM.EngineId, auth);
                }
            }
            return Encode(akey, pkey);
        }

        /// <summary>
        /// Encode SNMP version 3 packet
        /// </summary>
        /// <param name="authKey">Authentication key (not password)</param>
        /// <param name="privKey">Privacy key (not password)</param>
        /// <remarks>
        /// Before encoding the packet into a byte array you need to ensure all required information is
        /// set. Examples of required information is request type, Vbs (Oid + values pairs), USM settings including
        /// SecretName, authentication method and secret (if needed), privacy method and secret (if needed), etc.
        /// </remarks>
        /// <returns>Byte array BER encoded SNMP packet.</returns>
        public byte[] Encode(byte[] authKey, byte[] privKey)
        {
            MutableByte buffer = new MutableByte();
            // encode the global message data sequence header information

            MutableByte globalMessageData = new MutableByte();
            // if message id is 0 then generate a new, random message id
            if (_messageId.Value == 0)
            {
                Random rand = new Random();
                _messageId.Value = rand.Next(1, Int32.MaxValue);
            }

            // encode message id
            _messageId.Encode(globalMessageData);

            // encode max message size
            _maxMessageSize.Encode(globalMessageData);

            // message flags
            MsgFlags.Encode(globalMessageData);

            // security model code
            _securityModel.Value = USM.Type;
            _securityModel.Encode(globalMessageData);

            // add global message data to the main buffer
            // encode sequence header and add data
            AsnType.BuildHeader(buffer, SnmpConstants.SMI_SEQUENCE, globalMessageData.Length);
            buffer.Append(globalMessageData);

            MutableByte packetHeader = new MutableByte(buffer);

            // before going down this road, check if this is a discovery packet
            OctetString savedUserName = new OctetString();
            bool privacy = MsgFlags.Privacy;
            bool authentication = MsgFlags.Authentication;
            bool reportable = MsgFlags.Reportable;
            if (USM.EngineId.Length <= 0)
            {
                // save USM settings prior to encoding a Discovery packet
                savedUserName.Set(USM.SecurityName);
                USM.SecurityName.Reset(); // delete security name for discovery packets
                MsgFlags.Authentication = false;
                MsgFlags.Privacy = false;
                MsgFlags.Reportable = true;
            }

            USM.Encode(buffer);

            if (USM.EngineId.Length <= 0)
            {
                // restore saved USM values
                USM.SecurityName.Set(savedUserName);
                MsgFlags.Authentication = authentication;
                MsgFlags.Privacy = privacy;
                MsgFlags.Reportable = reportable;
            }

            // Check if privacy encryption is required
            MutableByte encodedPdu = new MutableByte();
            if (MsgFlags.Privacy && USM.EngineId.Length > 0)
            {
                IPrivacyProtocol privacyProtocol = PrivacyProtocol.GetInstance(USM.Privacy);
                if (privacyProtocol == null)
                {
                    throw new SnmpException(SnmpException.UnsupportedPrivacyProtocol, "Specified privacy protocol is not supported.");
                }

                // Get BER encoded ScopedPdu
                MutableByte unencryptedPdu = new MutableByte();
                ScopedPdu.Encode(unencryptedPdu);

                // we have to expand the key
                IAuthenticationDigest auth = Authentication.GetInstance(USM.Authentication);
                if (auth == null)
                {
                    throw new SnmpException(SnmpException.UnsupportedNoAuthPriv, "Invalid authentication protocol. noAuthPriv mode not supported.");
                }

                byte[] encryptedBuffer = privacyProtocol.Encrypt(unencryptedPdu, 0, unencryptedPdu.Length, privKey, USM.EngineBoots, USM.EngineTime, out byte[] privacyParameters, auth);

                USM.PrivacyParameters.Set(privacyParameters);
                OctetString encryptedOctetString = new OctetString(encryptedBuffer);
                encryptedOctetString.Encode(encodedPdu);
                // now redo packet encoding
                buffer.Reset();
                buffer.Set(packetHeader);
                USM.Encode(buffer);
                int preEncodedLength = encodedPdu.Length;
                buffer.Append(encodedPdu);
                if (_maxMessageSize.Value != 0)
                {
                    // verify compliance with maximum message size
                    if ((encodedPdu.Length - preEncodedLength) > _maxMessageSize)
                    {
                        throw new SnmpException(SnmpException.MaximumMessageSizeExceeded, "ScopedPdu exceeds maximum message size.");
                    }
                }
            }
            else
            {
                ScopedPdu.Encode(encodedPdu);
                buffer.Append(encodedPdu);
            }

            base.Encode(buffer);

            if (MsgFlags.Authentication && USM.EngineId.Length > 0)
            {
                USM.Authenticate(authKey, ref buffer);
                // Now re-encode the packet with the authentication information
                USM.Encode(packetHeader);
                packetHeader.Append(encodedPdu);
                base.Encode(packetHeader);
                buffer = packetHeader;
            }
            return buffer;
        }

        #endregion

        #region Helper methods

        /// <summary>
        /// Generate authentication key from authentication password and engine id
        /// </summary>
        /// <returns>Authentication key on success or null on failure</returns>
        public byte[] GenerateAuthenticationKey()
        {
            if (USM.EngineId == null || USM.EngineId.Length <= 0)
            {
                return null;
            }

            if (USM.AuthenticationSecret == null || USM.AuthenticationSecret.Length <= 0)
            {
                return null;
            }

            if (USM.Authentication != AuthenticationDigests.None)
            {
                IAuthenticationDigest authProto = SnmpSharpNet.Authentication.GetInstance(USM.Authentication);
                if (authProto != null)
                {
                    return authProto.PasswordToKey(USM.AuthenticationSecret, USM.EngineId);
                }
            }
            return null;
        }

        /// <summary>
        /// Generate privacy key from authentication password and engine id
        /// </summary>
        /// <returns>Privacy key on success or null on failure</returns>
        public byte[] GeneratePrivacyKey()
        {
            if (USM.Authentication == AuthenticationDigests.None)
            {
                return null;
            }

            if (USM.Privacy == PrivacyProtocols.None)
            {
                return null;
            }

            if (USM.PrivacySecret == null || USM.PrivacySecret.Length <= 0)
            {
                return null;
            }

            IAuthenticationDigest authProto = SnmpSharpNet.Authentication.GetInstance(USM.Authentication);
            if (authProto != null)
            {
                IPrivacyProtocol privProto = SnmpSharpNet.PrivacyProtocol.GetInstance(USM.Privacy);
                if (privProto != null)
                {
                    return privProto.PasswordToKey(USM.PrivacySecret, USM.EngineId, authProto);
                }
            }
            return null;
        }

        /// <summary>
        /// Build an SNMP version 3 packet suitable for use in discovery process.
        /// </summary>
        /// <returns>Discovery process prepared SNMP version 3 packet.</returns>
        public static SnmpV3Packet DiscoveryRequest()
        {
            SnmpV3Packet packet = new SnmpV3Packet(new ScopedPdu()); // with a blank scoped pdu
            // looking through other implementation, null (length 0) user name is used
            // packet.USM.SecurityName.Set("initial"); // set user name to initial, as described in RFCs
            return packet; // return packet
        }
        /// <summary>
        /// Build SNMP discovery response packet.
        /// </summary>
        /// <remarks>
        /// Manager application has to be able to respond to discovery requests to be able to handle
        /// SNMPv3 INFORM notifications.
        /// 
        /// In an INFORM packet, engineId value is set to the manager stations id (unlike all other requests
        /// where agent is the authoritative SNMP engine). For the agent to discover appropriate manager engine
        /// id, boots and time values (required for authentication and privacy packet handling), manager has to
        /// be able to respond to the discovery request.
        /// </remarks>
        /// <param name="messageId">Message id from the received discovery packet</param>
        /// <param name="requestId">Request id from the received discovery packets Pdu</param>
        /// <param name="engineId">Local engine id</param>
        /// <param name="engineBoots">Number of times local SNMP engine has been restarted</param>
        /// <param name="engineTime">Time since the engine was started in seconds</param>
        /// <param name="unknownEngineIdCount">Number of discovery packets received by the local SNMP engine</param>
        /// <returns>SNMP v3 packet properly formatted as a response to a discovery request</returns>
        public static SnmpV3Packet DiscoveryResponse(Int32 messageId, Int32 requestId, OctetString engineId, Int32 engineBoots, Int32 engineTime, Int32 unknownEngineIdCount)
        {
            SnmpV3Packet packet = new SnmpV3Packet();
            packet.Pdu.Type = PduType.Report;
            packet.Pdu.RequestId = requestId;
            packet.Pdu.VbList.Add(SnmpConstants.usmStatsUnknownEngineIDs, new Integer32(unknownEngineIdCount));
            // discovery response is a report packet. We don't want to receive reports about a report
            packet.MsgFlags.Reportable = false;
            packet.SetEngineId(engineId);
            packet.MessageId = messageId;
            packet.USM.EngineBoots = engineBoots;
            packet.USM.EngineTime = engineTime;
            return packet;
        }

        /// <summary>
        /// Build SNMP RESPONSE packet for the received INFORM packet.
        /// </summary>
        /// <returns>SNMP version 3 packet containing RESPONSE to the INFORM packet contained in the class instance.</returns>
        public SnmpV3Packet BuildInformResponse()
        {
            return SnmpV3Packet.BuildInformResponse(this);
        }

        /// <summary>
        /// Build SNMP RESPONSE packet for the INFORM packet class.
        /// </summary>
        /// <param name="informPacket">SNMP INFORM packet</param>
        /// <returns>SNMP version 3 packet containing RESPONSE to the INFORM packet contained in the parameter.</returns>
        /// <exception cref="SnmpInvalidPduTypeException">Parameter is not an INFORM SNMP version 3 packet class</exception>
        /// <exception cref="SnmpInvalidVersionException">Parameter is not a SNMP version 3 packet</exception>
        public static SnmpV3Packet BuildInformResponse(SnmpV3Packet informPacket)
        {
            if (informPacket.Version != SnmpVersion.Ver3)
            {
                throw new SnmpInvalidVersionException("INFORM packet can only be parsed from an SNMP version 3 packet.");
            }

            if (informPacket.Pdu.Type != PduType.Inform)
            {
                throw new SnmpInvalidPduTypeException("Inform response can only be built for INFORM packets.");
            }

            var response = new SnmpV3Packet(informPacket.ScopedPdu)
            {
                MessageId = informPacket.MessageId
            };
            response.USM.SecurityName.Set(informPacket.USM.SecurityName);
            response.USM.EngineTime = informPacket.USM.EngineTime;
            response.USM.EngineBoots = informPacket.USM.EngineBoots;
            response.USM.EngineId.Set(informPacket.USM.EngineId);
            response.USM.Authentication = informPacket.USM.Authentication;
            if( response.USM.Authentication != AuthenticationDigests.None )
            {
                response.USM.AuthenticationSecret.Set(informPacket.USM.AuthenticationSecret);
            }
            else
            {
                response.USM.AuthenticationSecret.Reset();
            }

            response.USM.Privacy = informPacket.USM.Privacy;
            if (response.USM.Privacy != PrivacyProtocols.None)
            {
                response.USM.PrivacySecret.Set(informPacket.USM.PrivacySecret);
            }
            else
            {
                response.USM.PrivacySecret.Reset();
            }

            response.MsgFlags.Authentication = informPacket.MsgFlags.Authentication;
            response.MsgFlags.Privacy = informPacket.MsgFlags.Privacy;
            response.MsgFlags.Reportable = informPacket.MsgFlags.Reportable;
            response.ScopedPdu.ContextEngineId.Set(informPacket.ScopedPdu.ContextEngineId);
            response.ScopedPdu.ContextName.Set(informPacket.ScopedPdu.ContextName);
            response.Pdu.Type = PduType.Response;
            response.Pdu.TrapObjectID.Set(informPacket.Pdu.TrapObjectID);
            response.Pdu.TrapSysUpTime.Value = informPacket.Pdu.TrapSysUpTime.Value;
            response.Pdu.RequestId = informPacket.Pdu.RequestId;

            return response;
        }

        #endregion
    }
}
