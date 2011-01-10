/************************************************************************************
 *    
 *  xmlrpcxx_client.cpp  (the XmlRpc++ version of the client -- Web Services version.)
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
 *       XmlRpc++       --- LGPL, Copyright (c) 2002-2003 by C. Morley
 *                          http://xmlrpcpp.sourceforge.net/
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

#define KEY_PASSWORD        "test"

#ifdef _WIN32

#define SERVER_PATH_DEFAULT	"C:\\~\\Open-Transactions\\testwallet\\data_folder"
#define CA_FILE             "certs\\special\\ca.crt"
#define KEY_FILE            "certs\\special\\client.pem"

#else

#define SERVER_PATH_DEFAULT	"/Users/REDACTED/Projects/Open-Transactions/testwallet/data_folder"
//#define SERVER_PATH_DEFAULT	"/home/ben/git-work/Open-Transactions/testwallet/data_folder"
#define CA_FILE             "certs/special/ca.crt"
#define KEY_FILE            "certs/special/client.pem"

#endif

// ---------------------------------------------------------------------------

#include <cstring>
#include <cstdio>
#include <cstdlib>

// ---------------------------------------------------------------------------

#include <iostream>

// ---------------------------------------------------------------------------

extern "C" 
{
#ifdef _WIN32
#include <WinSock.h>
#else
#include <netinet/in.h>
#endif
}

// ---------------------------------------------------------------------------

#include "XmlRpc.h"

using namespace XmlRpc;

// ---------------------------------------------------------------------------

#ifdef _WIN32
void OT_Sleep(int nMS);
#endif

// ---------------------------------------------------------------------------

#include "OTString.h"
#include "OTClient.h"
#include "OTServerConnection.h"
#include "OTMessage.h"
#include "OTString.h"
#include "OTWallet.h"
#include "OTPseudonym.h"
#include "OTEnvelope.h"
#include "OTCheque.h"
#include "OpenTransactions.h"
#include "OTPaymentPlan.h"
#include "OTLog.h"

// ---------------------------------------------------------------------------



// This global variable contains an OTWallet, an OTClient, etc. 
// It's the C++ high-level interace to OT. 
// Any client software will have an instance of this.
OT_API g_OT_API; 
// Note: Must call OT_API::Init() followed by g_OT_API.Init() in the main function, before using OT.


extern OTPseudonym *g_pTemporaryNym;


// ---------------------------------------------------------------------------


int main(int argc, char* argv[])
{
	OTLog::vOutput(0, "\n\nWelcome to Open Transactions... Test Client -- version %s\n"
				   "(transport build: OTMessage -> XmlRpc -> HTTP)\n", 
				   OTLog::Version());
	
	OT_API::InitOTAPI();
	
	// -----------------------------------------------------------------------
	
	
	OTString strCAFile, strKeyFile, strSSLPassword;
	
	if (argc < 2)
	{
		OTLog::vOutput(0, "\n==> USAGE:    %s   <SSL-password>  <absolute_path_to_data_folder>\n\n"
#if defined (FELLOW_TRAVELER)					   
					   "(Password defaults to '%s' if left blank.)\n"
					   "(Folder defaults to '%s' if left blank.)\n"
#else
					   "(The test password is always 'test'.\n'cd data_folder' then 'pwd' to see the absolute path.)\n"
#endif
					   "\n\n", argv[0]
#if defined (FELLOW_TRAVELER)					   
					   , KEY_PASSWORD, 
					   SERVER_PATH_DEFAULT
#endif					   
					   );
		
#if defined (FELLOW_TRAVELER)
		strSSLPassword.Set(KEY_PASSWORD);
		
		OTString strClientPath(SERVER_PATH_DEFAULT);
        g_OT_API.Init(strClientPath);  // SSL gets initialized in here, before any keys are loaded.
#else
		exit(1);
#endif
	}
	else if (argc < 3)
	{
		OTLog::vOutput(0, "\n==> USAGE:    %s   <SSL-password>  <absolute_path_to_data_folder>\n\n"
#if defined (FELLOW_TRAVELER)					      
					   "(Folder defaults to '%s' if left blank.)\n"
#endif
					   "\n\n", argv[0]
#if defined (FELLOW_TRAVELER)
					   , SERVER_PATH_DEFAULT
#endif
					   );
		
#if defined (FELLOW_TRAVELER)					   
		strSSLPassword.Set(argv[1]);
		
		OTString strClientPath(SERVER_PATH_DEFAULT);
        g_OT_API.Init(strClientPath);  // SSL gets initialized in here, before any keys are loaded.
#else
		exit(1);
#endif
	}
	else 
	{
		strSSLPassword.Set(argv[1]);
		
		OTString strClientPath(argv[2]);
        g_OT_API.Init(strClientPath);  // SSL gets initialized in here, before any keys are loaded.
	}	
	
	strCAFile. Format("%s%s%s", OTLog::Path(), OTLog::PathSeparator(), CA_FILE);
	strKeyFile.Format("%s%s%s", OTLog::Path(), OTLog::PathSeparator(), KEY_FILE);
	
	
	// -----------------------------------------------------------------------
	
	//
	// Basically, loop:
	//
	//	1) Present a prompt, and get a user string of input. Wait for that.
	//
	//	2) Process it out as an OTMessage to the server. It goes down the pipe.
	//
	//	3) Sleep for 1 second.
	//
	//	4) Awake and check for messages to be read in response from the server.
	//	   Loop. As long as there are any responses there, then process and handle
	//	   them all.
	//	   Then continue back up to the prompt at step (1).
	
    char buf[200] = "";
 	int retVal = 0;
	
	int nExpectResponse = 0;
	
	OTLog::Output(0, "\nYou may wish to 'load' then 'stat'.\n");
	OTLog::vOutput(4, "Starting client loop. u_header size in C code is %d.\n", OT_CMD_HEADER_SIZE);
	
	
	// Set the logging level for the network transport code.
	XmlRpc::setVerbosity(1);
	
	// -----------------------------------------------------------------------
	
	
	for(;;)
	{
		buf[0] = 0; // Making it fresh again.
		
		nExpectResponse = 0;
		
		// 1) Present a prompt, and get a user string of input. Wait for that.
		OTLog::Output(0, "\nWallet> ");
		
		if (NULL == fgets(buf, sizeof(buf)-10, stdin)) // Leaving myself 10 extra bytes at the end for safety's sake.
            break;
		
		OTLog::Output(0, ".\n..\n...\n....\n.....\n......\n.......\n........\n.........\n..........\n"
					  "...........\n............\n.............\n");
		
		// so we can process the user input
		std::string strLine = buf;
		
		// 1.5 The one command that doesn't involve a message to the server (so far)
		//     is the command to load the wallet from disk (which we do before we can
		//     do anything else.)  That and maybe the message to CONNECT to the server.
		// Load wallet.xml
		if (strLine.compare(0,4,"load") == 0)
		{
			OTLog::Output(0, "User has instructed to load wallet.xml...\n");
			g_OT_API.GetWallet()->LoadWallet("wallet.xml");
			
			//			g_OT_API.GetWallet()->SaveWallet("NEWwallet.xml"); // todo remove this test code.
			
			continue;
		}
		
		else if ('\0' == buf[0])
		{
			continue;
		}
		else if (strLine.compare(0,5,"clear") == 0)
		{
			if (NULL == g_pTemporaryNym)
			{
				OTLog::Output(0, "No Nym yet available. Try 'load'.\n");
				continue;
			}
			
			g_pTemporaryNym->RemoveAllNumbers();
			
			g_pTemporaryNym->SaveSignedNymfile(*g_pTemporaryNym);
			
			OTLog::Output(0, "Successfully removed all issued and transaction numbers. Saving nym...\n");
			continue;
		}			
		else if (strLine.compare(0,7,"payment") == 0)
		{
			if (NULL == g_pTemporaryNym)
			{
				OTLog::Output(0, "No Nym yet available to sign the payment plan with. Try 'load'.\n");
				continue;
			}
			
			OTLog::Output(0, "Enter your Asset Account ID that the payments will come from: ");
			OTString strTemp;
			strTemp.OTfgets(std::cin);
			
			const OTIdentifier ACCOUNT_ID(strTemp), USER_ID(*g_pTemporaryNym);
			OTAccount * pAccount = g_OT_API.GetWallet()->GetAccount(ACCOUNT_ID);
			
			if (NULL == pAccount)
			{
				OTLog::Output(0, "That account isn't loaded right now. Try 'load'.\n");
				continue;
			}
			
			// To write a payment plan, like a cheque, we need to burn one of our transaction numbers. (Presumably
			// the wallet is also storing a couple of these, since they are needed to perform any transaction.)
			//
			// I don't have to contact the server to write a payment plan -- as long as I already have a transaction
			// number I can use to write it. Otherwise I'd have to ask the server to send me one first.
			OTString strServerID(pAccount->GetRealServerID());
			long lTransactionNumber=0;
			
			if (false == g_pTemporaryNym->GetNextTransactionNum(*g_pTemporaryNym, strServerID, lTransactionNumber))
			{
				OTLog::Output(0, "Payment Plans are written offline, but you still need a transaction number\n"
							  "(and you have none, currently.) Try using 'n' to request another transaction number.\n");
				continue;
			}
			
			// -----------------------------------------------------------------------
			
			OTString str_RECIPIENT_USER_ID, str_RECIPIENT_ACCT_ID, strConsideration;
			
			// Get the Recipient Nym ID
			OTLog::Output(0, "Enter the Recipient's User ID (NymID): ");
			str_RECIPIENT_USER_ID.OTfgets(std::cin);		
			
			
			// THEN GET AN ACCOUNT ID in that same asset type
			OTLog::Output(0, "Enter the Recipient's ACCOUNT ID (of the same asset type as your account): ");
			str_RECIPIENT_ACCT_ID.OTfgets(std::cin);		
			
			OTLog::Output(0, "Enter a memo describing consideration for the payment plan: ");
			strConsideration.OTfgets(std::cin);		
			
			const OTIdentifier	RECIPIENT_USER_ID(str_RECIPIENT_USER_ID), 
			RECIPIENT_ACCT_ID(str_RECIPIENT_ACCT_ID);
			
			
			OTPaymentPlan thePlan(pAccount->GetRealServerID(), pAccount->GetAssetTypeID(),
								  pAccount->GetRealAccountID(),	pAccount->GetUserID(),
								  RECIPIENT_ACCT_ID, RECIPIENT_USER_ID);
			
			// -----------------------------------------------------------------------
			
			// Valid date range (in seconds)
			OTLog::Output(0, 
						  " 6 minutes	==      360 Seconds\n"
						  "10 minutes	==      600 Seconds\n"
						  "1 hour		==     3600 Seconds\n"
						  "1 day		==    86400 Seconds\n"
						  "30 days			==  2592000 Seconds\n"
						  "3 months		==  7776000 Seconds\n"
						  "6 months		== 15552000 Seconds\n\n"
						  );
			
			long lExpirationInSeconds = 86400;
			OTLog::vOutput(0, "How many seconds before payment plan expires? (defaults to 1 day: %ld): ", lExpirationInSeconds);
			strTemp.Release();
			strTemp.OTfgets(std::cin);
			
			if (strTemp.GetLength() > 1)
				lExpirationInSeconds = atol(strTemp.Get());
			
			
			// -----------------------------------------------------------------------
			
			time_t	VALID_FROM	= time(NULL); // This time is set to TODAY NOW
			
			OTLog::vOutput(0, "Payment plan becomes valid for processing STARTING date\n"
						   "(defaults to now, in seconds) [%ld]: ", VALID_FROM);
			strTemp.Release();
			strTemp.OTfgets(std::cin);
			
			if (strTemp.GetLength() > 2)
				VALID_FROM = atol(strTemp.Get());
			
			const time_t VALID_TO = VALID_FROM + lExpirationInSeconds; // now + 86400
			
			// -----------------------------------------------------------------------
			
			bool bSuccessSetAgreement = thePlan.SetAgreement(lTransactionNumber, strConsideration, VALID_FROM,	VALID_TO);
			
			if (!bSuccessSetAgreement)
			{
				OTLog::Output(0, "Failed trying to set the agreement!\n");
				
				// IF FAILED, ADD TRANSACTION NUMBER BACK TO LIST OF AVAILABLE NUMBERS.
				g_pTemporaryNym->AddTransactionNum(*g_pTemporaryNym, strServerID, lTransactionNumber, true); // bSave=true								

				continue;
			}
			
			bool bSuccessSetInitialPayment	= true; // the default, in case user chooses not to even have this payment.
			bool bSuccessSetPaymentPlan		= true; // the default, in case user chooses not to have a payment plan
			// -----------------------------------------------------------------------
			
			OTLog::Output(0, "What is the Initial Payment Amount, if any? [0]: ");
			strTemp.Release(); strTemp.OTfgets(std::cin);
			long lInitialPayment = atol(strTemp.Get());
			
			if (lInitialPayment > 0)
			{
				time_t	PAYMENT_DELAY = 60; // 60 seconds.
				
				OTLog::vOutput(0, "From the Start Date forward, how long until the Initial Payment should charge?\n"
							   "(defaults to one minute, in seconds) [%d]: ", PAYMENT_DELAY);
				strTemp.Release();
				strTemp.OTfgets(std::cin);
				
				if ((strTemp.GetLength() > 1) && atol(strTemp.Get())>0)
					PAYMENT_DELAY = atol(strTemp.Get());
				
				// -----------------------------------------------------------------------
				
				bSuccessSetInitialPayment = thePlan.SetInitialPayment(lInitialPayment, PAYMENT_DELAY);
			}
			
			if (!bSuccessSetInitialPayment)
			{
				OTLog::Output(0, "Failed trying to set the initial payment!\n");
				
				// IF FAILED, ADD TRANSACTION NUMBER BACK TO LIST OF AVAILABLE NUMBERS.
				g_pTemporaryNym->AddTransactionNum(*g_pTemporaryNym, strServerID, lTransactionNumber, true); // bSave=true								
				
				continue;
			}
			
			// -----------------------------------------------------------------------
			
			OTLog::Output(0, "What is the regular payment amount, if any? [0]: ");
			strTemp.Release(); strTemp.OTfgets(std::cin);
			long lRegularPayment = atol(strTemp.Get());
			
			if (lRegularPayment > 0) // If there are regular payments.
			{
				// -----------------------------------------------------------------------
				
				time_t	PAYMENT_DELAY = 120; // 120 seconds.
				
				OTLog::vOutput(0, "From the Start Date forward, how long until the Regular Payments start?\n"
							   "(defaults to two minutes, in seconds) [%d]: ", PAYMENT_DELAY);
				strTemp.Release();
				strTemp.OTfgets(std::cin);
				
				if ((strTemp.GetLength() > 1) && atol(strTemp.Get())>0)
					PAYMENT_DELAY = atol(strTemp.Get());
				
				// -----------------------------------------------------------------------
				
				time_t	PAYMENT_PERIOD = 30; // 30 seconds.
				
				OTLog::vOutput(0, "Once payments begin, how much time should elapse between each payment?\n"
							   "(defaults to thirty seconds) [%d]: ", PAYMENT_PERIOD);
				strTemp.Release();
				strTemp.OTfgets(std::cin);
				
				if ((strTemp.GetLength() > 1) && atol(strTemp.Get())>0)
					PAYMENT_PERIOD = atol(strTemp.Get());
				
				// -----------------------------------------------------------------------
				
				time_t	PLAN_LENGTH = 0; // 0 seconds (for no max length).
				
				OTLog::vOutput(0, "From start date, do you want the plan to expire after a certain maximum time?\n"
							   "(defaults to 0 for no) [%d]: ", PLAN_LENGTH);
				strTemp.Release();
				strTemp.OTfgets(std::cin);
				
				if (strTemp.GetLength() > 1)
					PLAN_LENGTH = atol(strTemp.Get());
				
				// -----------------------------------------------------------------------
				
				OTLog::Output(0, "Should there be some maximum number of payments? (Zero for no maximum.) [0]: ");
				strTemp.Release(); strTemp.OTfgets(std::cin);
				int nMaxPayments = atoi(strTemp.Get());
				
				bSuccessSetPaymentPlan = thePlan.SetPaymentPlan(lRegularPayment, PAYMENT_DELAY, PAYMENT_PERIOD, PLAN_LENGTH, nMaxPayments);
			}
			
			if (!bSuccessSetPaymentPlan)
			{
				OTLog::Output(0, "Failed trying to set the payment plan!\n");
				
				// IF FAILED, ADD TRANSACTION NUMBER BACK TO LIST OF AVAILABLE NUMBERS.
				g_pTemporaryNym->AddTransactionNum(*g_pTemporaryNym, strServerID, lTransactionNumber, true); // bSave=true								
				
				continue;
			}
			
			thePlan.SignContract(*g_pTemporaryNym);
			thePlan.SaveContract();
			
			OTString strPlan(thePlan);
			
			OTLog::vOutput(0, "\n\n(Make sure Both Parties sign the payment plan before submitting to server):\n\n\n%s\n", 
						   strPlan.Get());
			
			continue;			
		}
		
		
		else if (strLine.compare(0,6,"cheque") == 0)
		{
			if (NULL == g_pTemporaryNym)
			{
				OTLog::Output(0, "No Nym yet available to sign the cheque with. Try 'load'.\n");
				continue;
			}
			
			
			OTLog::Output(0, "Enter the ID for your Asset Account that the cheque will be drawn on: ");
			OTString strTemp;
			strTemp.OTfgets(std::cin);
			
			const OTIdentifier ACCOUNT_ID(strTemp), USER_ID(*g_pTemporaryNym);
			OTAccount * pAccount = g_OT_API.GetWallet()->GetAccount(ACCOUNT_ID);
			
			if (NULL == pAccount)
			{
				OTLog::Output(0, "That account isn't loaded right now. Try 'load'.\n");
				continue;
			}
			
			// To write a cheque, we need to burn one of our transaction numbers. (Presumably the wallet
			// is also storing a couple of these, since they are needed to perform any transaction.)
			//
			// I don't have to contact the server to write a cheque -- as long as I already have a transaction
			// number I can use to write it. Otherwise I'd have to ask the server to send me one first.
			OTString strServerID(pAccount->GetRealServerID());
			long lTransactionNumber=0;
			
			if (false == g_pTemporaryNym->GetNextTransactionNum(*g_pTemporaryNym, strServerID, lTransactionNumber))
			{
				OTLog::Output(0, "Cheques are written offline, but you still need a transaction number\n"
							  "(and you have none, currently.) Try using 'n' to request another transaction number.\n");
				continue;
			}
			
			
			OTCheque theCheque(pAccount->GetRealServerID(), pAccount->GetAssetTypeID());
			
			// Recipient
			OTLog::Output(0, "Enter a User ID for the recipient of this cheque (defaults to blank): ");
			OTString strRecipientUserID;
			strRecipientUserID.OTfgets(std::cin);
			const OTIdentifier RECIPIENT_USER_ID(strRecipientUserID.Get());
			
			// Amount
			OTLog::Output(0, "Enter an amount: ");
			strTemp.Release();
			strTemp.OTfgets(std::cin);
			const long lAmount = atol(strTemp.Get());
			
			// -----------------------------------------------------------------------
			
			// Memo
			OTLog::Output(0, "Enter a memo for your check: ");
			OTString strChequeMemo;
			strChequeMemo.OTfgets(std::cin);
			
			// -----------------------------------------------------------------------
			
			// Valid date range (in seconds)
			OTLog::Output(0, 
						  " 6 minutes	==      360 Seconds\n"
						  "10 minutes	==      600 Seconds\n"
						  "1 hour		==     3600 Seconds\n"
						  "1 day		==    86400 Seconds\n"
						  "30 days	==  2592000 Seconds\n"
						  "3 months	==  7776000 Seconds\n"
						  "6 months	== 15552000 Seconds\n\n"
						  );
			
			long lExpirationInSeconds = 3600;
			OTLog::vOutput(0, "How many seconds before cheque expires? (defaults to 1 hour: %ld): ", lExpirationInSeconds);
			strTemp.Release();
			strTemp.OTfgets(std::cin);
			
			if (strTemp.GetLength() > 1)
				lExpirationInSeconds = atol(strTemp.Get());
			
			
			// -----------------------------------------------------------------------
			
			time_t	VALID_FROM	= time(NULL); // This time is set to TODAY NOW
			
			OTLog::vOutput(0, "Cheque may be cashed STARTING date (defaults to now, in seconds) [%ld]: ", VALID_FROM);
			strTemp.Release();
			strTemp.OTfgets(std::cin);
			
			if (strTemp.GetLength() > 2)
				VALID_FROM = atol(strTemp.Get());
			
			
			const time_t VALID_TO = VALID_FROM + lExpirationInSeconds; // now + 3600
			
			// -----------------------------------------------------------------------
			
			bool bIssueCheque = theCheque.IssueCheque(lAmount, lTransactionNumber, VALID_FROM, VALID_TO, 
													  ACCOUNT_ID, USER_ID, strChequeMemo,
													  (strRecipientUserID.GetLength() > 2) ? &(RECIPIENT_USER_ID) : NULL);
			
			if (bIssueCheque)
			{
				theCheque.SignContract(*g_pTemporaryNym);
				theCheque.SaveContract();
				
				OTString strCheque(theCheque);
				
				OTLog::vOutput(0, "\n\nOUTPUT:\n\n\n%s\n", strCheque.Get());
			}
			else 
			{
				OTLog::Output(0, "Failed trying to issue the cheque!\n");
				
				// IF FAILED, ADD TRANSACTION NUMBER BACK TO LIST OF AVAILABLE NUMBERS.
				g_pTemporaryNym->AddTransactionNum(*g_pTemporaryNym, strServerID, lTransactionNumber, true); // bSave=true								
			}
			
			continue;
		}
		
		else if (strLine.compare(0,7,"decrypt") == 0)
		{
			if (NULL == g_pTemporaryNym)
			{
				OTLog::Output(0, "No Nym yet available to decrypt with.\n");
				continue;
			}
			
			OTLog::Output(0, "Enter text to be decrypted:\n> ");
			
			OTASCIIArmor theArmoredText;
			char decode_buffer[200]; // Safe since we only read sizeof - 1
			
			do {
				decode_buffer[0] = 0;
				if (NULL != fgets(decode_buffer, sizeof(decode_buffer)-1, stdin))
				{
					theArmoredText.Concatenate("%s\n", decode_buffer);
					OTLog::Output(0, "> ");
				}
				else 
				{
					break;
				}
			} while (strlen(decode_buffer)>1);
			
			
			OTEnvelope	theEnvelope(theArmoredText);
			OTString	strDecodedText;
			
			theEnvelope.Open(*g_pTemporaryNym, strDecodedText);
			
			OTLog::vOutput(0, "\n\nDECRYPTED TEXT:\n\n%s\n\n", strDecodedText.Get());
			
			continue;
		}
		
		else if (strLine.compare(0,6,"decode") == 0)
		{
			OTLog::Output(0, "Enter text to be decoded:\n> ");
			
			OTASCIIArmor theArmoredText;
			char decode_buffer[200]; // Safe since we only read sizeof - 1.
			
			do {
				decode_buffer[0] = 0;
				if (NULL != fgets(decode_buffer, sizeof(decode_buffer)-1, stdin))
				{
					theArmoredText.Concatenate("%s\n", decode_buffer);
					OTLog::Output(0, "> ");
				}
				else 
				{
					break;
				}
				
			} while (strlen(decode_buffer)>1);
			
			OTString strDecodedText(theArmoredText);
			
			OTLog::vOutput(0, "\n\nDECODED TEXT:\n\n%s\n\n", strDecodedText.Get());
			
			continue;
		}
		
		else if (strLine.compare(0,6,"encode") == 0)
		{
			OTLog::Output(0, "Enter text to be ascii-encoded (terminate with ~ on a new line):\n> ");
			
			OTString strDecodedText;
			char decode_buffer[200]; // Safe since we only read sizeof - 1.
			
			do {
				decode_buffer[0] = 0;
				
				if ((NULL != fgets(decode_buffer, sizeof(decode_buffer)-1, stdin)) &&
					(decode_buffer[0] != '~'))
				{
					strDecodedText.Concatenate("%s", decode_buffer);
					OTLog::Output(0, "> ");
				}
				else 
				{
					break;
				}
				
			} while (decode_buffer[0] != '~');
			
			OTASCIIArmor theArmoredText(strDecodedText);
			
			OTLog::vOutput(0, "\n\nENCODED TEXT:\n\n%s\n\n", theArmoredText.Get());
			
			continue;
		}
		
		else if (strLine.compare(0,4,"hash") == 0)
		{
			OTLog::Output(0, "Enter text to be hashed (terminate with ~ on a new line):\n> ");
			
			OTString strDecodedText;
			char decode_buffer[200]; // Safe since we only read sizeof - 1.
			
			do {
				decode_buffer[0] = 0;
				
				if ((NULL != fgets(decode_buffer, sizeof(decode_buffer)-1, stdin)) &&
					(decode_buffer[0] != '~'))
				{
					strDecodedText.Concatenate("%s\n", decode_buffer);
					OTLog::Output(0, "> ");
				}
				else 
				{
					break;
				}
				
			} while (decode_buffer[0] != '~');
			
			OTIdentifier theIdentifier;
			theIdentifier.CalculateDigest(strDecodedText);
			
			OTString strHash(theIdentifier);
			
			OTLog::vOutput(0, "\n\nMESSAGE DIGEST:\n\n%s\n\n", strHash.Get());
			
			continue;
		}
		
		else if (strLine.compare(0,4,"stat") == 0)
		{
			OTLog::Output(0, "User has instructed to display wallet contents...\n");
			
			OTString strStat;
			g_OT_API.GetWallet()->DisplayStatistics(strStat);
			OTLog::vOutput(0, "%s\n", strStat.Get());
			
			continue;
		}
		
		else if (strLine.compare(0,4,"help") == 0)
		{
			OTLog::Output(0, "User has instructed to display the help file...\n");
			
			system("more ../docs/CLIENT-COMMANDS.txt");
						
			continue;
		}
		
		else if (strLine.compare(0,4,"quit") == 0)
		{
			OTLog::Output(0, "User has instructed to exit the wallet...\n");
			
			break;
		}
		
		
		// ------------------------------------------------------------------------------			
		
		// ALL commands in this test client will simply pull up the first server on the list
		// and connect to it, and send the message there. It will then receive the reply and 
		// disconnect. Each new message is a new connection (ala HTTP).
		//
		// So that's what this code here does. But in a REAL GUI, the server would be SELECTED
		// on a list (on the screen somewhere) and the code would use the selected server, instead
		// of always using the first server in the list, like this test client does.
		//
		// Usually an operation will involve an account, and each account has the server ID,
		// which the client software will simply use to lookup the server's host and port,
		// and the xml-rpc call will process out from there.
		
		OTIdentifier	SERVER_ID;
		OTString		SERVER_NAME;
		
		OTServerContract * pServerContract = NULL;
		
		if (NULL == g_OT_API.GetWallet())
		{
			OTLog::Output(0, "The wallet object is still NULL, somehow. Please load it.\n");
			continue;
		}	// Here, for testing, I'm just grabbing the first server in the wallet...
		else if (false == g_OT_API.GetWallet()->GetServer(0, SERVER_ID, SERVER_NAME))
		{
			OTLog::Output(0, "There are no server contracts in the wallet. Try 'load'.\n");
			continue;
		}
		else if (NULL == (pServerContract = g_OT_API.GetWallet()->GetServerContract(SERVER_ID)))
		{
			OTLog::Error("Strange -- got a server contract ID based on index, but then no contract was found at that same index.\n");
			continue;
		}
		
		// ------------------------------------------------------------------------------			
		
		// You can't just connect to any hostname and port.
		// Instead, you give me the Server Contract, and *I'll* look up all that stuff FOR you...
		// (We verify this up here, but use it at the bottom of the function once the message is set up.)
		//
		int			nServerPort = 0;
		OTString	strServerHostname;
		
		if (false == pServerContract->GetConnectInfo(strServerHostname, nServerPort))
		{
			OTLog::Error("Failed retrieving connection info from server contract.\n");
			continue;
		}
		
		// ------------------------------------------------------------------------------			
		
		bool bSendCommand	= false; // Determines whether to actually send a message to the server.
		
		OTMessage theMessage;
		
		// If we can match the user's request to a client command,
		// AND theClient object is able to process that request into
		// theMessage, then we send it down the pipe.
		
		if (g_pTemporaryNym) // by this point I also know that pServerContract is good.
		{
			// In lieu of maintaining a constant connection to the server, in RPC mode, the
			// client updates its internal "connection" object to make sure the right pointers
			// are in place (since in RPC mode, each message could be from a different nym 
			// and to a different server.)
			//
			g_OT_API.GetClient()->SetFocusToServerAndNym(*pServerContract, *g_pTemporaryNym, &OT_XmlRpcCallback);
			// NOTE -- This MAY be unnecessary for ProcessUserCommand (since these args are passed
			// in there already) but it's definitely necessary soon after for ProcessServerReply()
			// (which comes next.)
			
			// -------------------------------------------------------------------------
			
			// 'check server ID' command
			if (buf[0] == 'c')
			{
				OTLog::vOutput(0, "(User has instructed to send a checkServerID command to the server...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::checkServerID, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{				
					bSendCommand = true;
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
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::createUserAccount, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
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
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::checkUser, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing checkUser command in ProcessMessage: %c\n", buf[0]);
				// ------------------------------------------------------------------------
			}
			
			// sendUserMessage
			else if (buf[0] == 's')
			{
				OTLog::Output(0, "(User has instructed to send a sendUserMessage command to the server...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::sendUserMessage, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing sendUserMessage command in ProcessMessage: %c\n", buf[0]);
				// ------------------------------------------------------------------------
			}
			
			// register new asset account 
			else if (buf[0] == 'a')
			{
				OTLog::Output(0, "(User has instructed to send a createAccount command to the server...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::createAccount, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
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
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::issueAssetType, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing issueAssetType command in ProcessMessage: %s\n", buf);
				// ------------------------------------------------------------------------
			}
			
			// issue a new basket asset type 
			else if (!strcmp(buf, "basket\n"))
			{
				OTLog::Output(0, "(User has instructed to send an issueBasket command to the server...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::issueBasket, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing issueBasket command in ProcessMessage: %s\n", buf);
				// ------------------------------------------------------------------------
			}
			
			// exchange in/out of a basket currency 
			else if (!strcmp(buf, "exchange\n"))
			{
				OTLog::Output(0, "(User has instructed to send an exchangeBasket command to the server...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::exchangeBasket, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing exchangeBasket command in ProcessMessage: %s\n", buf);
				// ------------------------------------------------------------------------
			}
			
			// make an offer and put it onto a market. 
			else if (!strcmp(buf, "offer\n"))
			{
				OTLog::Output(0, "(User has instructed to send a marketOffer command to the server...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::marketOffer, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing marketOffer command in ProcessMessage: %s\n", buf);
				// ------------------------------------------------------------------------
			}
			
			// Set a Server Contract's client-side name (merely a label.) 
			else if (!strcmp(buf, "setservername\n"))
			{
				OTLog::Output(0, "(User wants to set a Server Contract's client-side name...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::setServerName, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					//					bSendCommand = true; // No message needed. Local data only.
				}
				// ------------------------------------------------------------------------
			}
			
			// Set an Asset Contract's client-side name (merely a label.) 
			else if (!strcmp(buf, "setassetname\n"))
			{
				OTLog::Output(0, "(User wants to set an Asset Contract's client-side name...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::setAssetName, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					//					bSendCommand = true; // No message needed. Local data only.
				}
				// ------------------------------------------------------------------------
			}
			
			// Set a Nym's client-side name (merely a label.) 
			else if (!strcmp(buf, "setnymname\n"))
			{
				OTLog::Output(0, "(User wants to set a Nym's client-side name...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::setNymName, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					//					bSendCommand = true; // No message needed. Local data only.
				}
				// ------------------------------------------------------------------------
			}
			
			// Set an Asset Account's client-side name (merely a label.) 
			else if (!strcmp(buf, "setaccountname\n"))
			{
				OTLog::Output(0, "(User wants to set an Asset Account's client-side name...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::setAccountName, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					//					bSendCommand = true; // No message needed. Local data only.
				}

				// ------------------------------------------------------------------------
			}
			
			// get nymbox 
			else if (buf[0] == 'y')
			{
				OTLog::Output(0, "(User has instructed to send a getNymbox command to the server...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::getNymbox, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing getNymbox command in ProcessMessage: %c\n", buf[0]);
				// ------------------------------------------------------------------------
			}
			
			// get inbox 
			else if (buf[0] == 'i')
			{
				OTLog::Output(0, "(User has instructed to send a getInbox command to the server...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::getInbox, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing getInbox command in ProcessMessage: %c\n", buf[0]);
				// ------------------------------------------------------------------------
			}
			
			// get outbox 
			else if (buf[0] == 'o')
			{
				OTLog::Output(0, "(User has instructed to send a getOutbox command to the server...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::getOutbox, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing getOutbox command in ProcessMessage: %c\n", buf[0]);
				// ------------------------------------------------------------------------
			}
			
			// deposit cheque
			else if (buf[0] == 'q')
			{
				OTLog::Output(0, "User has instructed to deposit a cheque...\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::notarizeCheque, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
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
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::withdrawVoucher, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
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
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::notarizeWithdrawal, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
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
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::notarizeDeposit, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing deposit command in ProcessMessage: %c\n", buf[0]);
				// ------------------------------------------------------------------------
			}
			
			// activate payment plan
			else if (!strcmp(buf, "plan\n"))
			{
				OTLog::Output(0, "User has instructed to activate a payment plan...\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::paymentPlan, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing payment plan command in ProcessMessage: %c\n", buf[0]);
				// ------------------------------------------------------------------------
			}
			
			// deposit purse
			else if (buf[0] == 'p')
			{
				OTLog::Output(0, "(User has instructed to deposit a purse containing cash...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::notarizePurse, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing deposit command in ProcessMessage: %c\n", buf[0]);
				// ------------------------------------------------------------------------
			}
			
			// get account 
			else if (!strcmp(buf, "get\n"))
			{
				OTLog::Output(0, "(User has instructed to send a getAccount command to the server...)\n");
				
				// ------------------------------------------------------------------------------			
				// if successful setting up the command payload...
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::getAccount, theMessage, 
															 *g_pTemporaryNym,  *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
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
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::getContract, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing getContract command in ProcessMessage: %c\n", buf[0]);
				// ------------------------------------------------------------------------
			}
			
			
			// sign contract 
			// This doesn't message the server, but it DOES require the user's Nym to be loaded.
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
				char decode_buffer[200]; // Safe since we only read sizeof(decode_buffer)-1
				
				do {
					decode_buffer[0] = 0; // Make it fresh.
					
					if ((NULL != fgets(decode_buffer, sizeof(decode_buffer)-1, stdin)) &&
						(decode_buffer[0] != '~'))
					{
						if (!bEscaped && decode_buffer[0] == '-')
						{
							strContract.Concatenate("- ");
						}
						strContract.Concatenate("%s", decode_buffer);
						OTLog::Output(0, "> ");
					}
					else 
					{
						break;
					}
					
				} while (decode_buffer[0] != '~');
				
				OTAssetContract theContract;
				theContract.CreateContract(strContract, *g_pTemporaryNym);
				
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
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::getMint, theMessage, 
															 *g_pTemporaryNym,  *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
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
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::notarizeTransfer, theMessage, 
															 *g_pTemporaryNym,  *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
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
				
				if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::getRequest, theMessage, 
															 *g_pTemporaryNym, *pServerContract,
															 NULL)) // NULL pAccount on this command.
				{
					bSendCommand = true;
				}
				else
					OTLog::vError("Error processing getRequest command in ProcessMessage: %c\n", buf[0]);
				// ------------------------------------------------------------------------
			}
			
			// getTransactionNum
			else if (buf[0] == 'n')
			{
				// I just coded (here) for myself a secret option (for testing)...
				// Optionally instead of JUST 'n', I can put n <number>, (without brackets) and
				// this code will add that number to my list of issued and transaction numbers.
				// I already have the ability to clear the list, so now I can add numbers to it as well.
				// (Which adds to both lists.)
				// I can also remove a number from the transaction list but LEAVE it on the issued list,
				// for example by writing a cheque and throwing it away.
				//
				// This code is for testing and allows me to find and patch any problems without
				// having to re-create my data each time -- speeds up debugging.
				//
				long lTransactionNumber = ((strlen(buf) > 2) ? atol(&(buf[2])) : 0);
				
				if (lTransactionNumber > 0)
				{
					OTString strServerID;
					pServerContract->GetIdentifier(strServerID);
					
					g_pTemporaryNym->AddTransactionNum(*g_pTemporaryNym, strServerID, lTransactionNumber, true); // bool bSave=true
					
					OTLog::vOutput(0, "Transaction number %ld added to both lists (on client side.)\n", 
								   lTransactionNumber);
				}
				
				else 
				{
					OTLog::Output(0, "(User has instructed to send a getTransactionNum command to the server...)\n");
					
					// ------------------------------------------------------------------------------			
					// if successful setting up the command payload...
					
					if (g_OT_API.GetClient()->ProcessUserCommand(OTClient::getTransactionNum, theMessage, 
													  *g_pTemporaryNym,  *pServerContract,
													  NULL)) // NULL pAccount on this command.
					{
						bSendCommand = true;
					}
					else
						OTLog::vError("Error processing getTransactionNum command in ProcessMessage: %c\n", buf[0]);
				}
				
				// ------------------------------------------------------------------------
			}
			
			else 
			{
				if( 1 )
				{
					//gDebugLog.Write("unknown user command in ProcessMessage in main.cpp");
					OTLog::Output(0, "\n");
					//				OTLog::vError( "unknown user command in ProcessMessage in main.cpp: %d\n", buf[0]);
				}		
				continue;
			}
		} //if (g_pTemporaryNym)
		
		else
		{
			//		OTLog::Error( "Your command was unrecognized or required resources that were not loaded.\n");
			OTLog::Output(0, "\n");
		}
		
		// -----------------------------------------------------------
		
		const OTPseudonym * pServerNym = pServerContract->GetContractPublicNym();
		
		if (bSendCommand && (NULL != pServerNym))
		{
			OTString strEnvelopeContents;
			// Save the ready-to-go message into a string.
			theMessage.SaveContract(strEnvelopeContents);
			
			OTEnvelope theEnvelope;
			// Seal the string up into an encrypted Envelope
			theEnvelope.Seal(*pServerNym, strEnvelopeContents);
			
			OTASCIIArmor ascEnvelope(theEnvelope); // ascEnvelope now contains the base64-encoded string of the sealed envelope contents.
			
			if (ascEnvelope.Exists())
			{
				// Here's our connection...
#if defined (linux)
				XmlRpcClient theXmlRpcClient(strServerHostname.Get(), nServerPort, 0); // serverhost, port.
#else
				XmlRpcClient theXmlRpcClient(strServerHostname.Get(), nServerPort); // serverhost, port.
#endif
				// -----------------------------------------------------------
				//
				// Call the OT_XML_RPC method (thus passing the message to the server.)
				//
				XmlRpcValue oneArg, result;		// oneArg contains the outgoing message; result will contain the server reply.
				oneArg[0] = ascEnvelope.Get();	// Here's where I set the envelope string, as the only argument for the rpc call.
				
				if (theXmlRpcClient.execute("OT_XML_RPC", oneArg, result)) // The actual call to the server. (Hope my envelope string isn't too long for this...)
				{					
					std::string str_Result = result;
					OTASCIIArmor ascServerReply = str_Result.c_str();
					
					OTEnvelope theServerEnvelope(ascServerReply);
					OTString	strServerReply;				// Maybe should use g_OT_API.GetClient()->GetNym or some such...
					bool bOpened = theServerEnvelope.Open(*g_pTemporaryNym, strServerReply);
					
					OTMessage * pServerReply = new OTMessage;
					
					OT_ASSERT(NULL != pServerReply);
					
					if (bOpened && strServerReply.Exists() && pServerReply->LoadContractFromString(strServerReply))
					{
						// Now the fully-loaded message object (from the server, this time) can be processed by the OT library...
						g_OT_API.GetClient()->ProcessServerReply(*pServerReply); // Client takes ownership and will handle cleanup.
					}
					else
					{
						delete pServerReply;
						pServerReply = NULL;
						OTLog::Error("Error loading server reply from string after call to 'OT_XML_RPC'\n");
					}
				}
				else
				{
					OTLog::Error("Error calling 'OT_XML_RPC' over the XmlRpc transport layer.\n");
				}
			}
		} // if bSendCommand		
		
		// Sleep for 1 second.
#ifdef _WIN32
		OT_Sleep(1000);
#else
		sleep (1);
#endif
	} // for
	
	// -----------------------------------------------------------

		
	OTLog::Output(0, "Finished running rpc client.\n");
	
#ifdef _WIN32
	WSACleanup();
#endif
	
	return 0;
}

