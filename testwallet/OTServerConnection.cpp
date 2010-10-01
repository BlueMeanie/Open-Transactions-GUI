/************************************************************************************
 *    
 *  OTServerConnection.cpp
 *  
 *              Open Transactions:  Library, Protocol, Server, and Test Client
 *    
 *                      -- Anonymous Numbered Accounts
 *                      -- Untraceable Digital Cash
 *                      -- Triple-Signed Receipts
 *                      -- Basket Currencies
 *                      -- Signed XML Contracts
 *    
 *    Copyright (C) 2010 by "Fellow Traveler" (A pseudonym)
 *    
 *    EMAIL:
 *    F3llowTraveler@gmail.com --- SEE PGP PUBLIC KEY IN CREDITS FILE.
 *    
 *    KEY FINGERPRINT:
 *    9DD5 90EB 9292 4B48 0484  7910 0308 00ED F951 BB8E
 *    
 *    WEBSITE:
 *    http://www.OpenTransactions.org
 *    
 *    OFFICIAL PROJECT WIKI:
 *    http://wiki.github.com/FellowTraveler/Open-Transactions/
 *    
 *     ----------------------------------------------------------------
 *    
 *    Open Transactions was written including these libraries:
 *    
 *       Lucre          --- Copyright (C) 1999-2009 Ben Laurie.
 *                          http://anoncvs.aldigital.co.uk/lucre/
 *       irrXML         --- Copyright (C) 2002-2005 Nikolaus Gebhardt
 *                          http://irrlicht.sourceforge.net/author.html	
 *       easyzlib       --- Copyright (C) 2008 First Objective Software, Inc.
 *                          Used with permission. http://www.firstobject.com/
 *       PGP to OpenSSL --- Copyright (c) 2010 Mounir IDRASSI 
 *                          Used with permission. http://www.idrix.fr
 *       SFSocket       --- Copyright (C) 2009 Matteo Bertozzi
 *                          Used with permission. http://th30z.netsons.org/
 *    
 *     ----------------------------------------------------------------
 *
 *    Open Transactions links to these libraries:
 *    
 *       OpenSSL        --- (Version 1.0.0a at time of writing.) 
 *                          http://openssl.org/about/
 *       zlib           --- Copyright (C) 1995-2004 Jean-loup Gailly and Mark Adler
 *    
 *     ----------------------------------------------------------------
 *
 *    LICENSE:
 *        This program is free software: you can redistribute it and/or modify
 *        it under the terms of the GNU Affero General Public License as
 *        published by the Free Software Foundation, either version 3 of the
 *        License, or (at your option) any later version.
 *    
 *        You should have received a copy of the GNU Affero General Public License
 *        along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *      
 *        If you would like to use this software outside of the free software
 *        license, please contact FellowTraveler. (Unfortunately many will run
 *        anonymously and untraceably, so who could really stop them?)
 *   
 *        This library is also "dual-license", meaning that Ben Laurie's license
 *        must also be included and respected, since the code for Lucre is also
 *        included with Open Transactions.
 *        The Laurie requirements are light, but if there is any problem with his
 *        license, simply remove the deposit/withdraw commands. Although there are 
 *        no other blind token algorithms in Open Transactions (yet), the other 
 *        functionality will continue to operate.
 *    
 *    OpenSSL WAIVER:
 *        This program is released under the AGPL with the additional exemption 
 *        that compiling, linking, and/or using OpenSSL is allowed.
 *    
 *    DISCLAIMER:
 *        This program is distributed in the hope that it will be useful,
 *        but WITHOUT ANY WARRANTY; without even the implied warranty of
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *        GNU Affero General Public License for more details.
 *      
 ************************************************************************************/

#include <cstring>
#include <cstdio>

extern "C" 
{
#ifdef _WIN32
#include <WinSock.h>
#define strcasecmp _stricmp
#else
#include <netinet/in.h>
#endif

#include "SSL-Example/SFSocket.h"
}


#include "OTServerConnection.h"

#include "OTIdentifier.h"
#include "OTDataCheck.h"
#include "OTPayload.h"
#include "OTWallet.h"
#include "OTPseudonym.h"
#include "OTMessage.h"
#include "OTMessageBuffer.h"
#include "OTWallet.h"
#include "OTClient.h"
#include "OTEnvelope.h"

#include "OTLog.h"



int allow_debug = 1;

/*
 union u_header
 {
 BYTE buf[OT_CMD_HEADER_SIZE];
 struct {
 BYTE type_id;    // 1 byte
 BYTE command_id; // 1 byte
 BYTE filler[2];
 uint32_t size;     // 4 bytes to describe size of payload
 BYTE  checksum;  // 1 byte
 } fields;  // total of 9 bytes
 };
 */

void SetupHeader( u_header & theCMD, int nTypeID, int nCmdID, OTPayload & thePayload)
{
	uint32_t lSize = thePayload.GetSize(); // outputting in normal byte order, but sent to network in network byte order.

	theCMD.fields.type_id	= nTypeID;
	theCMD.fields.command_id= nCmdID;
//	theCMD.fields.size		= thePayload.GetSize();
	theCMD.fields.size		= htonl(lSize); // think this is causing problems.. maybe not...
	theCMD.fields.checksum	= CalcChecksum(theCMD.buf, OT_CMD_HEADER_SIZE-1);	
	
	
	BYTE byChecksum	= (BYTE)theCMD.fields.checksum;
	int nChecksum	= byChecksum;
	
	OTLog::vOutput(4, "OT_CMD_HEADER_SIZE: %d -- CMD TYPE: %d -- CMD NUM: %d -- (followed by 2 bytes of filler)\n"
			"PAYLOAD SIZE: %d -- CHECKSUM: %d\n", OT_CMD_HEADER_SIZE,
			nTypeID, nCmdID, lSize, nChecksum);
	
	OTLog::vOutput(5, "First 9 bytes are: %d %d %d %d %d %d %d %d %d\n",
//			"sizeof(int) is %d, sizeof(long) is %d, sizeof(short) is %d, sizeof(uint32_t) is %d.\n", 
			theCMD.buf[0],theCMD.buf[1],theCMD.buf[2],theCMD.buf[3],theCMD.buf[4], theCMD.buf[5], theCMD.buf[6], theCMD.buf[7], theCMD.buf[8]
//			sizeof(int), sizeof(long), sizeof(short), sizeof(uint32_t)
			);
}


bool OTServerConnection::s_bInitialized = false;

void OTServerConnection::Initialize()
{
	// We've already been initialized. We can just return
	if (s_bInitialized)
	{
		return;
	}
	
	// This is the first time this function has run.
	s_bInitialized = true; // set this to true so the function can't run again. It only runs the first time.
	
	// Initialize SSL
    SFSocketGlobalInit();
}


// the hostname is not a reference, because I want people to be able
// to pass in a C-style string and have it still work.
bool OTServerConnection::Connect(OTPseudonym & theNym, OTServerContract & theServerContract,
								 OTString & strCA_FILE, OTString & strKEY_FILE, OTString & strKEY_PASSWORD)
{
	// We're already connected!
	if (IsConnected())
		return false;
	
	// Make sure all the socket stuff is initialized and set up.
	Initialize();
	
	// You can't just pass in a hostname and port.
	// Instead, you pass in the Nym and Contract, and *I'll* look up all that stuff.
	OTString strHostname;
	int nPort;
	
	if (false == theServerContract.GetConnectInfo(strHostname, nPort))
	{
		OTLog::Output(0,  "Failed retrieving connection info from server contract.\n");
		return false;
	}
	
    SFSocket * socket;

    // Alloc Socket
	socket = SFSocketAlloc();
	
	OT_ASSERT_MSG(NULL != socket, "SFSocketAlloc Failed\n");
			
    // Initialize SSL client Socket
    if (SFSocketInit(socket, strCA_FILE.Get(), NULL, strKEY_FILE.Get(), strKEY_PASSWORD.Get(), NULL) < 0) {
	    OTLog::Error("Init Failed\n");
        return false;
    }
	
	// TODO: Note, I had to go intside this function and comment out the Cert-checking portion
	// in order to get this program running.
	// So I need to go back and revisit that later, but at least now we have client/server.
	
    // Connect to Host
    if (SFSocketConnectToHost(socket, strHostname.Get(), nPort) < 0) {
        OTLog::Output(0, "Connect to Host Failed\n");
        return false;
    }	
	
	m_pSocket			= socket;
	m_pNym				= &theNym;
	m_pServerContract	= &theServerContract;
	
	return true;
}



// When the server sends a reply back with our new request number, we
// need to update our records accordingly.
//
// This function is meant to be called when that happens, so that we
// can do just that.
//
void OTServerConnection::OnServerResponseToGetRequestNumber(long lNewRequestNumber)
{
	if (m_pNym && m_pServerContract)
	{
		OTLog::vOutput(1,  "Received new request number from the server: %ld. Updating Nym records...\n", 
				lNewRequestNumber);
		
		OTString strServerID;
		m_pServerContract->GetIdentifier(strServerID);
		m_pNym->OnUpdateRequestNum(*m_pNym, strServerID, lNewRequestNumber);
	}
	else {
		OTLog::Error("Expected m_pNym or m_pServerContract to be not null in "
				"OTServerConnection::OnServerResponseToGetRequestNumber.\n");
	}
}


bool OTServerConnection::GetServerID(OTIdentifier & theID)
{
	if (m_pServerContract)
	{
		m_pServerContract->GetIdentifier(theID);
		return true;
	}
	return false;
}

// When a certain Nym opens a certain account on a certain server,
// that account is put onto a list of accounts inside the wallet.
// Therefore, a certain Nym's connection to a certain server will
// occasionally require access to those accounts. Therefore the
// server connection object needs to have a pointer to the wallet.
// There might be MORE THAN ONE connection per wallet, or only one,
// but either way the connections need a pointer to the wallet
// they are associated with, so they can access those accounts.
OTServerConnection::OTServerConnection(OTWallet & theWallet, OTClient & theClient, SFSocket * pSock)
{
	m_pSocket			= pSock;
	m_pNym				= NULL;
	m_pServerContract	= NULL;
	m_pWallet			= &theWallet;
	m_pClient			= &theClient;
}

OTServerConnection::OTServerConnection(OTWallet & theWallet, OTClient & theClient)
{
	m_pSocket			= NULL;
	m_pNym				= NULL;
	m_pServerContract	= NULL;
	m_pWallet			= &theWallet;
	m_pClient			= &theClient;
}

OTServerConnection::~OTServerConnection()
{
	if (m_pSocket)
	{
	    // Close and Release Socket Resources
		SFSocketRelease(m_pSocket);	
	}
}


// This function returns true if we received a full and proper reply from the server.
// theServerReply will contain that message after a successful call to this function.
bool OTServerConnection::ProcessInBuffer(OTMessage & theServerReply)
{
	int  err;
	uint32_t nread;
	u_header theCMD;
	
	// clear the header
	memset((void *)theCMD.buf, 0, OT_CMD_HEADER_SIZE);
	
	for (nread = 0;  nread < OT_CMD_HEADER_SIZE;  nread += err)
	{
		err = SFSocketRead(m_pSocket, theCMD.buf + nread, OT_CMD_HEADER_SIZE - nread);

#ifdef _WIN32
		if (0 == err || SOCKET_ERROR == err) // 0 is a disconnect. error is error. otherwise err contains bytes read.
#else
		if (err <= 0)
#endif
		{
			break;
		}
	}
	
	if (OT_CMD_HEADER_SIZE == nread)
	{
		OTLog::vOutput(4, "\n**************************************************************\n"
				"===> Processing header from server reply. First 5 bytes are: %d %d %d %d %d...\n",
				theCMD.buf[0],theCMD.buf[1],theCMD.buf[2],theCMD.buf[3],theCMD.buf[4]);	
		
		
		return ProcessReply(theCMD, theServerReply);
	}
	
	return false;
}

// ProcessInBuffer calls this function, once it has verified the header,
// this function gets the payload.  If successful, returns true and theServerReply
// will contain the OTMessage that was received.
// It also flushes the pipe in the event of any errors.
bool OTServerConnection::ProcessReply(u_header & theCMD, OTMessage & theServerReply)
{
	bool bSuccess = false;

	
	OTLog::vOutput(4, "\n****************************************************************\n"
			"===> Processing header from server response.\nFirst 9 bytes are: %d %d %d %d %d %d %d %d %d...\n",
			theCMD.buf[0],theCMD.buf[1],theCMD.buf[2],theCMD.buf[3],theCMD.buf[4],theCMD.buf[5], theCMD.buf[6], theCMD.buf[7], theCMD.buf[8]);

	
	if( theCMD.fields.type_id == CMD_TYPE_1 )
	{
		OTLog::Output(3, "Received a Type 1 Command...\n");
		
		if( IsChecksumValid( theCMD.buf, OT_CMD_HEADER_SIZE ) )
		{								
			OTLog::Output(3, "Checksum is valid! Processing payload.\n");
			
			if (true == ProcessType1Cmd(theCMD, theServerReply ))
				bSuccess = true;
		}
		else {
			OTLog::Error("Invalid checksum - Type 1 Command\n");
		}
	}
	else
	{
		//gDebugLog.Write("Unknown command type");
		int nCMDType = theCMD.fields.type_id;
		OTLog::vError("Unknown command type: %d\n", nCMDType);
	}
	
	
	// I added this for error correction. In the event that there are errors, 
	// just clean out whatever is in the pipe and throw it away.
	// Should probably send an Error message back, as well.
	if (bSuccess == false)
	{
		int  err = 0, nread = 0;
		
		char buffer[1024];
		int sizeJunkData = 1024;
		
		while (1)
		{
			err = SFSocketRead(m_pSocket, buffer, sizeJunkData);
			
			if (err > 0) // _WIN32
				nread += err;
			
#ifdef _WIN32
			if (0 == err || SOCKET_ERROR == err) // 0 means disconnect. error means error. >0 means bytes read.
#else
			if (err <= 0)
#endif
				break;
		}
		
		OTLog::vError("Transmission error--therefore have flushed the pipe, discarding %d bytes.\n", 
				nread, sizeJunkData);
	}
	
	return bSuccess;
}



// If this function returns a true, that means theServerReply now contains a valid message
// from the server.  (So something should be done with it.)
bool OTServerConnection::ProcessType1Cmd(u_header & theCMD, OTMessage & theServerReply)
{
	// At this point, the checksum has already validated. 
	// Might as well get the PAYLOAD next.
	int  err;
	uint32_t nread;
	
	// Make sure our byte-order is correct here.
	theCMD.fields.size = ntohl(theCMD.fields.size); // think this is causing problems... maybe not...

	OTPayload thePayload;
	thePayload.SetPayloadSize(theCMD.fields.size);
	
	for (nread = 0;  nread < theCMD.fields.size;  nread += err)
	{
		err = SFSocketRead(m_pSocket, (unsigned char *)thePayload.GetPayloadPointer() + nread, theCMD.fields.size - nread);

#ifdef _WIN32
		if (0 == err || SOCKET_ERROR == 0) // 0 means disconnect. error means error. otherwise, err contains bytes read.
#else
		if (err <= 0)
#endif
			break;
	}
	
	// ------------------------------------------------------------
	
	switch (theCMD.fields.command_id) {
		case TYPE_1_CMD_1:
			OTLog::Output(3,  "Received TYPE 1 CMD 1, an OTMessage.\n");
			break;
		case TYPE_1_CMD_2:
			OTLog::vOutput(3, "Received TYPE 1 CMD 2, an OTEnvelope containing an OTMessage.\n");
			break;
		default:
			break;
	}
	
	// ------------------------------------------------------------
	
	if (theCMD.fields.size == 0)
	{
		OTLog::Error("(The payload was a 0 size.)\n");
		return true;
	}
	else if (nread < theCMD.fields.size)
	{
		OTLog::vError("Number of bytes read (%d) did NOT match size in header (%d).\n",
				nread, theCMD.fields.size);
		return false;
	}
	else
	{
		OTLog::vOutput(4,  "Loaded a payload, size: %d\n", theCMD.fields.size);
	}
	// ------------------------------------------------------------
	

	// a signed OTMessage
	if (TYPE_1_CMD_1 == theCMD.fields.command_id) 
	{
#ifdef _WIN32
		if (OTPAYLOAD_GetMessage(thePayload, theServerReply))
#else
		if (thePayload.GetMessage(theServerReply))
#endif
		{
			OTLog::Output(4, "Successfully retrieved payload message...\n");
			
			if (theServerReply.ParseRawFile())
			{
				OTLog::Output(4, "Successfully parsed payload message.\n");
				
				OTPseudonym * pServerNym = NULL;
				
				if (m_pServerContract && (pServerNym = (OTPseudonym *)m_pServerContract->GetContractPublicNym()))
				{
					if (theServerReply.VerifySignature((const OTPseudonym &)*pServerNym))
					{
						OTLog::Output(0, "VERIFIED -- this message was signed by the Server.\n");
					}
					else {
						OTLog::Output(0, "Signature verification failed on this message, proportedly from the Server.\n");
						return false;
					}
				}
				else {
					OTLog::Output(0, "No server contract loaded, or could not load public key from server contract.\n");
					return false;
				}
				
				return true;
			}
			else {
				OTLog::Error("Error parsing message.\n");
				return false;
			}
			
		}
		else {
			OTLog::Error("Error retrieving message from payload.\n");
			return false;
		}
		
	}
	
	// A base64-encoded envelope, encrypted, and containing a signed message.
	else if (TYPE_1_CMD_2 == theCMD.fields.command_id) 
	{
		OTEnvelope theEnvelope;
		if (thePayload.GetEnvelope(theEnvelope))
		{
			OTLog::Output(3, "===> Received encrypted envelope. (Server reply.) Decrypting...\n");
			
			OTString strEnvelopeContents;
						
			// Decrypt the Envelope.
			if (m_pNym && theEnvelope.Open(*m_pNym, strEnvelopeContents))
			{
				// All decrypted, now let's load the results into an OTMessage.
				// No need to call theMessage.ParseRawFile() after, since
				// LoadContractFromString handles it.
				//
				if (theServerReply.LoadContractFromString(strEnvelopeContents))
				{
					OTLog::Output(4, "Success decrypting the message out of the envelope and parsing it.\n");
					
					OTPseudonym * pServerNym = NULL;
					
					if (m_pServerContract && (pServerNym = (OTPseudonym *)m_pServerContract->GetContractPublicNym()))
					{
						if (theServerReply.VerifySignature((const OTPseudonym &)*pServerNym))
						{
							OTLog::Output(0, "VERIFIED -- this message was signed by the Server.\n");
//							OTLog::vOutput(0,  "VERIFIED -- this message was signed by the Server:\n%s\n", strEnvelopeContents.Get());
						}
						else 
						{
							OTLog::Output(0,  "Signature verification failed on this message, purportedly from the Server.\n");
							return false;
						}
					}
					else {
						OTLog::Error("No server contract loaded, or could not load public key from server contract.\n");
						return false;
					}
					
					return true;
				}
				else 
				{
					OTLog::Error("Error loading message from envelope contents.\n");
					return false;		
				}
			}
			else {
				OTLog::Error("Unable to open envelope.\n");
				return false;
			}			
		}
		else {
			OTLog::Error("Error retrieving message from payload.\n");
			return false;
		}
		
	}
		
	else {
		OTLog::Error("Error retrieving message from payload. Unknown type.\n");
		return false;
	}
	
	return true;
	
}




bool OTServerConnection::SignAndSend(OTMessage & theMessage)
{
	if (m_pNym && m_pSocket && m_pWallet && theMessage.SignContract(*m_pNym) && theMessage.SaveContract())
	{
		ProcessMessageOut(theMessage);
		return true;
	}
	
	return false;
}




void OTServerConnection::ProcessMessageOut(OTMessage & theMessage)
{
    int  err;
	uint32_t nwritten;
	
	u_header theCMD; 
	OTPayload thePayload;
	
	// clear the header
	memset((void *)theCMD.buf, 0, OT_CMD_HEADER_SIZE);

	// Here is where we set up the Payload (so we have the size ready before the header goes out)
	// This is also where we have turned on the encrypted envelopes  }:-)

	// Testing encrypted envelopes...
	const OTPseudonym * pRecipient = NULL;
	
	if (m_pServerContract && (pRecipient = m_pServerContract->GetContractPublicNym()))
	{
		OTString strEnvelopeContents;
		// Save the ready-to-go message into a string.
		theMessage.SaveContract(strEnvelopeContents);
		
		OTEnvelope theEnvelope;
		// Seal the string up into an encrypted Envelope
		theEnvelope.Seal(*pRecipient, strEnvelopeContents);
		
		// From here on out, theMessage is disposable. OTPayload takes over. 
		// OTMessage doesn't care about checksums and headers.
		thePayload.SetEnvelope(theEnvelope);
		
		// Now that the payload is ready, we'll set up the header.
		SetupHeader(theCMD, CMD_TYPE_1, TYPE_1_CMD_2, thePayload);
	}
	// else, for whatever reason, we just send an UNencrypted message...
	else {
		thePayload.SetMessage(theMessage);
		
		// Now that the payload is ready, we'll set up the header.
		SetupHeader(theCMD, CMD_TYPE_1, TYPE_1_CMD_1, thePayload);
	}
	
	int nHeaderSize = OT_CMD_HEADER_SIZE;
	
	for (nwritten = 0;  nwritten < nHeaderSize;  nwritten += err)
	{
		err = SFSocketWrite(m_pSocket, theCMD.buf + nwritten, nHeaderSize - nwritten);

#ifdef _WIN32
		if (0 == err || SOCKET_ERROR == err) //  0 is disonnect. error is error. >0 is bytes written.
#else
		if (err <= 0)
#endif
			break;
	}

	// At this point, we have sent the header across the pipe.
	uint32_t nPayloadSize = thePayload.GetSize();
	
	for (nwritten = 0;  nwritten < nPayloadSize;  nwritten += err)
	{
		err = SFSocketWrite(m_pSocket, (unsigned char *)thePayload.GetPayloadPointer() + nwritten, nPayloadSize - nwritten);

#ifdef _WIN32
		if (0 == err || SOCKET_ERROR == err) //  0 is disonnect. error is error. >0 is bytes written.
#else
		if (err <= 0)
#endif
			break;
	}		
	OTLog::Output(0, "Message sent...\n\n");
	// At this point, we have sent the payload across the pipe.		
}



// This function interprets test input (so should have been in test client?)
// then it uses that to send a message to server.
// The buf passed in is simply data collected by fgets from stdin.
void OTServerConnection::ProcessMessageOut(char *buf, int * pnExpectReply)
{
 	bool bSendCommand = false;
	bool bSendPayload = false;
	
	OTMessage theMessage;
	
	bool bHandledIt = false;
	
    int  err;
	uint32_t nwritten;
	u_header theCMD; 
	
	// clear the header
	memset((void *)theCMD.buf, 0, OT_CMD_HEADER_SIZE);
	
	
	// Simple rule here: In each of the below if statements,
	// YOU MUST set up the header bytes HERE!
	// OR you must set the boolean bSendCommand TO TRUE!!
	// It must be one or the other in each block.
	// If you set to true, code at the bottom will calculate header
	// for you. If you fail to do this, the header is now uncalculated either way.
	// Don't send uncalculated headers to the server unless doing it on purpose for TESTING.
	
	if (buf[0] == '1')
	{
		bHandledIt = true;
		
		theCMD.fields.type_id = CMD_TYPE_1;
		theCMD.fields.command_id = TYPE_1_CMD_1;
		theCMD.fields.size = 0;
		theCMD.fields.checksum = CalcChecksum(theCMD.buf, OT_CMD_HEADER_SIZE-1);
		
		int nChecksum = theCMD.fields.checksum;
		
		OTLog::vOutput(0, "(User has instructed to send a size %d, TYPE 1 COMMAND to the server...)\n CHECKSUM: %d\n", 
				OT_CMD_HEADER_SIZE, nChecksum);
		bSendCommand = true;
	}
	else if (buf[0] == '2')
	{
		bHandledIt = true;
		
		theCMD.fields.type_id = 12;
		theCMD.fields.command_id = 3;
		theCMD.fields.size = 98;
		theCMD.fields.checksum = CalcChecksum(theCMD.buf, OT_CMD_HEADER_SIZE-1);
		
		OTLog::vOutput(0, "(User has instructed to send a size %d, **malformed command** to the server...)\n", OT_CMD_HEADER_SIZE+3);
		bSendCommand = true;
	}
	// Empty OTMessage including signed XML, but no other commands
	else if (buf[0] == '3')
	{
		OTLog::vOutput(0, "(User has instructed to create a signed XML message and send it to the server...)\n");
		bHandledIt = true;
		
		// Normally you'd update the member variables here, before signing it.
		// But this is just an empty OTMessage.
		
		// When a message is signed, it updates its m_xmlUnsigned contents to the values in the members variables
		m_pWallet->SignContractWithFirstNymOnList(theMessage);
		
		// SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
		// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
		theMessage.SaveContract();
		
		bSendCommand = true;
		bSendPayload = true;
	}
	
	
	// Above are various test messages.
	
	// ------------------------------------------------------------------------------			
	
	// ------------------------------------------------------------------------------			
	
	// This section for commands that involve building full XML messages, 
	// that is, most of the real implementation of the transaction protocol.
	
	// If we can match the user's request to a client command,
	// AND theClient object is able to process that request into
	// a payload, THEN we create the header and send it all down the pipe.
	
	if (false == bHandledIt && m_pNym && m_pServerContract)
	{
		// check server ID command
		if (buf[0] == 'c')
		{
			OTLog::vOutput(0, "(User has instructed to send a checkServerID command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::checkServerID, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{				
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing checkServerID command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// register new user account 
		else if (buf[0] == 'r')
		{
			OTLog::Output(0, "(User has instructed to send a createUserAccount command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::createUserAccount, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing createUserAccount command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// ALL MESSAGES BELOW THIS POINT SHOULD ATTACH A REQUEST NUMBER IF THEY EXPECT THE SERVER TO PROCESS THEM.
		// (Handled inside ProcessUserCommand)
		
		// checkUser
		else if (buf[0] == 'u')
		{
			OTLog::Output(0, "(User has instructed to send a checkUser command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::checkUser, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing checkUser command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// register new asset account 
		else if (buf[0] == 'a')
		{
			OTLog::Output(0, "(User has instructed to send a createAccount command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::createAccount, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing createAccount command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// issue a new asset type 
		else if (!strcmp(buf, "issue\n"))
		{
			OTLog::Output(0, "(User has instructed to send an issueAssetType command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::issueAssetType, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing issueAssetType command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// issue a new basket asset type 
		else if (!strcmp(buf, "basket\n"))
		{
			OTLog::Output(0, "(User has instructed to send an issueBasket command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::issueBasket, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing issueBasket command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// exchange in/out of a basket currency 
		else if (!strcmp(buf, "exchange\n"))
		{
			OTLog::Output(0, "(User has instructed to send an exchangeBasket command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::exchangeBasket, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing exchangeBasket command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// get inbox 
		else if (buf[0] == 'i')
		{
			OTLog::Output(0, "(User has instructed to send a getInbox command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::getInbox, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing getInbox command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// deposit cheque
		else if (buf[0] == 'q')
		{
			OTLog::Output(0, "User has instructed to deposit a cheque...\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::notarizeCheque, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing deposit cheque command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// withdraw voucher
		else if (buf[0] == 'v')
		{
			OTLog::Output(0, "User has instructed to withdraw a voucher (like a cashier's cheque)...\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::withdrawVoucher, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing withdraw voucher command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// withdraw cash
		else if (buf[0] == 'w')
		{
			OTLog::Output(0, "(User has instructed to withdraw cash...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::notarizeWithdrawal, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing withdraw command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// deposit tokens
		else if (buf[0] == 'd')
		{
			OTLog::Output(0, "(User has instructed to deposit cash tokens...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::notarizeDeposit, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing deposit command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// deposit purse
		else if (buf[0] == 'p')
		{
			OTLog::Output(0, "(User has instructed to deposit a purse containing cash...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::notarizePurse, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing deposit command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// get account 
		else if (!strcmp(buf, "test\n"))
		{
			OTLog::vOutput(0, "(User has instructed to perform a test...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pNym)
			{
				OTString strMessage("Well well well, this is just a little bit of plaintext.\nNotice there are NO NEWLINES at the start.\n"
									"I'm just trying to make it as long as i can, so that\nI can test the envelope and armor functionality.\n");
				
				OTLog::vOutput(0, "MESSAGE:\n------>%s<--------\n", strMessage.Get());
				
				OTASCIIArmor ascMessage(strMessage);
				
				OTLog::vOutput(0, "ASCII ARMOR:\n------>%s<--------\n", ascMessage.Get());

				OTEnvelope theEnvelope;
				theEnvelope.Seal(*m_pNym, strMessage);
				
				ascMessage.Release();
				
				theEnvelope.GetAsciiArmoredData(ascMessage);
				
				OTLog::vOutput(0, "ENCRYPTED PLAIN TEXT AND THEN ASCII ARMOR:\n------>%s<--------\n", ascMessage.Get());
				
				strMessage.Release();
				
				OTEnvelope the2Envelope(ascMessage);
				the2Envelope.Open(*m_pNym, strMessage);
				
				OTLog::vOutput(0, "DECRYPTED PLAIN TEXT:\n------>%s<--------\n", strMessage.Get());
				
				OTEnvelope the3Envelope;
				the3Envelope.Seal(*m_pNym, strMessage.Get());
				
				ascMessage.Release();
				
				the3Envelope.GetAsciiArmoredData(ascMessage);
				
				OTLog::vOutput(0, "RE-ENCRYPTED PLAIN TEXT AND THEN ASCII ARMOR:\n------>%s<--------\n", ascMessage.Get());

				strMessage.Release();
				
				OTEnvelope the4Envelope(ascMessage);
				the4Envelope.Open(*m_pNym, strMessage);
				
				OTLog::vOutput(0, "RE-DECRYPTED PLAIN TEXT:\n------>%s<--------\n", strMessage.Get());
				
				OTEnvelope the5Envelope;
				the5Envelope.Seal(*m_pNym, strMessage.Get());
				
				ascMessage.Release();
				
				the3Envelope.GetAsciiArmoredData(ascMessage);
				
				OTLog::vOutput(0, "RE-RE-ENCRYPTED PLAIN TEXT AND THEN ASCII ARMOR:\n------>%s<--------\n", ascMessage.Get());
				
				strMessage.Release();
				
				OTEnvelope the6Envelope(ascMessage);
				the6Envelope.Open(*m_pNym, strMessage);
				
				OTLog::vOutput(0, "RE-RE-DECRYPTED PLAIN TEXT:\n------>%s<--------\n", strMessage.Get());
				
			}
			
			// ------------------------------------------------------------------------
		}
		
		// get account 
		else if (!strcmp(buf, "get\n"))
		{
			OTLog::Output(0, "(User has instructed to send a getAccount command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::getAccount, theMessage, 
											*m_pNym,  *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing getAccount command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// get contract 
		else if (!strcmp(buf, "getcontract\n"))
		{
			OTLog::Output(0, "(User has instructed to send a getContract command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::getContract, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing getContract command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		
		// sign contract 
		else if (!strcmp(buf, "signcontract\n"))
		{
			OTLog::Output(0, "Is the contract properly escaped already? [y/n]: ");
			// User input.
			// I need a from account, Yes even in a deposit, it's still the "From" account.
			// The "To" account is only used for a transfer. (And perhaps for a 2-way trade.)
			OTString strEscape;
			strEscape.OTfgets(std::cin);
//			strEscape.OTfgets(std::cin);
			                    
			char cEscape='n';
			bool bEscaped = strEscape.At(0, cEscape);

			if (bEscaped)
			{
				if ('N' == cEscape || 'n' == cEscape)
					bEscaped = false;
			}
				
			OTLog::Output(0, "Please enter an unsigned asset contract; terminate with ~ on a new line:\n> ");
			OTString strContract;
			char decode_buffer[200];
			
			do {
				fgets(decode_buffer, sizeof(decode_buffer), stdin);
				
				if (decode_buffer[0] != '~')
				{
					if (!bEscaped && decode_buffer[0] == '-')
					{
						strContract.Concatenate("- ");
					}
					strContract.Concatenate("%s", decode_buffer);
					OTLog::Output(0, "> ");
				}
			} while (decode_buffer[0] != '~');
			
			OTAssetContract theContract;
			theContract.CreateContract(strContract, *m_pNym);
			
			// re-using strContract here for output this time.
			strContract.Release();
			theContract.SaveContract(strContract);
			
			OTLog::vOutput(0, ".\n..\n...\n....\n.....\n......\n.......\n........\n.........\n\n"
					"NEW CONTRACT:\n\n%s\n", strContract.Get());
			// ------------------------------------------------------------------------
		}
		
		// get mint 
		else if (!strcmp(buf, "getmint\n"))
		{
			OTLog::Output(0, "(User has instructed to send a getMint command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::getMint, theMessage, 
											*m_pNym,  *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing getMint command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// notarize transfer 
		else if (buf[0] == 't')
		{
			OTLog::Output(0, "(User has instructed to send a Transfer command (Notarize Transactions) to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::notarizeTransfer, theMessage, 
											*m_pNym,  *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing notarizeTransactions command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// getRequest
		else if (buf[0] == 'g')
		{
			OTLog::Output(0, "(User has instructed to send a getRequest command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::getRequest, theMessage, 
											*m_pNym, *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing getRequest command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		// getTransactionNum
		else if (buf[0] == 'n')
		{
			OTLog::Output(0, "(User has instructed to send a getTransactionNum command to the server...)\n");
			
			// ------------------------------------------------------------------------------			
			// if successful setting up the command payload...
			
			if (m_pClient->ProcessUserCommand(OTClient::getTransactionNum, theMessage, 
											*m_pNym,  *m_pServerContract,
											NULL)) // NULL pAccount on this command.
			{
				bSendCommand = true;
				bSendPayload = true;				
			}
			else
				OTLog::vError("Error processing getTransactionNum command in ProcessMessage: %c\n", buf[0]);
			// ------------------------------------------------------------------------
		}
		
		else 
		{
			if( allow_debug )
			{
				//gDebugLog.Write("unknown user command in ProcessMessage in main.cpp");
				OTLog::Output(0, "\n");
				//				OTLog::vError( "unknown user command in ProcessMessage in main.cpp: %d\n", buf[0]);
			}		
			return;
		}
	} //if (false == bHandledIt && m_pNym && m_pServerContract)
	
	else if (false == bHandledIt)
	{
		//		OTLog::Error( "Your command was unrecognized or required resources that were not loaded.\n");
		OTLog::Output(0, "\n");
	}
	
	if (bSendCommand && bSendPayload)
	{
		// Voila -- it's sent. (If there was a payload involved.)
		ProcessMessageOut(theMessage);
	} // Otherwise...
	else if (bSendCommand)
	{
		int nHeaderSize = OT_CMD_HEADER_SIZE;
		
		// TODO: REMOVE THIS. FOR TESTING ONLY
		if (buf[0] == '2') {
			nHeaderSize += 3;
		}
		
		for (nwritten = 0;  nwritten < nHeaderSize;  nwritten += err)
		{
			err = SFSocketWrite(m_pSocket, theCMD.buf + nwritten, nHeaderSize - nwritten);

#ifdef _WIN32
		if (0 == err || SOCKET_ERROR == err) //  0 is disonnect. error is error. >0 is bytes written.
#else
		if (err <= 0)
#endif				
			break;
		}
		
		int n0 = theCMD.buf[0], n1 = theCMD.buf[1], n2 = theCMD.buf[2], n3 = theCMD.buf[3], n4 = theCMD.buf[4], n5 = theCMD.buf[5], n6 = theCMD.buf[6];
		
		OTLog::vOutput(4, "Sent: %d %d %d %d %d %d %d\n", n0, n1, n2, n3, n4, n5, n6);
	}
	// At this point, we have sent the header across the pipe.
}



