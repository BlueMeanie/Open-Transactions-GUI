/************************************************************************************
 *    
 *  testclient.cpp  (the actual command line test client that encapsulates OTClient)
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
#else
#include <netinet/in.h>
#endif

#include "SSL-Example/SFSocket.h"
}


#ifdef _WIN32
void OT_Sleep(int nMS);
#endif

#include "OTIdentifier.h"
#include "OTString.h"
#include "OTClient.h"
#include "OTServerConnection.h"
#include "OTMessage.h"
#include "OTString.h"
#include "OTWallet.h"
#include "OTPseudonym.h"
#include "OTEnvelope.h"
#include "OTCheque.h"
#include "OTAgreement.h"
#include "OpenTransactions.h"
#include "OTPaymentPlan.h"
#include "OTLog.h"



// This global variable contains an OTWallet, an OTClient, etc. 
// It's the C++ high-level interace to OT. 
// Any client software will have an instance of this.
OT_API g_OT_API; 
// Note: Must call OT_API::Init() followed by g_OT_API.Init() in the main function, before using OT.


extern OTPseudonym *g_pTemporaryNym;


// TODO REALLY NEED to move this crap to a config file...
// ALso, FYI, the below paths may not work unless you put a fully-qualified path (which I haven't.)
#define KEY_PASSWORD        "test"  // RIGHT NOW THE PASSWORD FOR CONNECTING TO THE SERVER IS HARDCODED HERE.  TODO: config file, password prompt.

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

// NOTE: this SSL connection is entirely different from the user's cert/pubkey that he uses for his UserID while 
// talking to the server. I may be using the same key for that, but this code here is not about my wallet talking
// to its mint. Rather, it's about an SSL client app talking to an SSL server, at a lower layer, before my app's
// intelligence takes over.  Just like when you use SSH to connect somewhere on a terminal. There is some immediate
// key negotiation going on. Once connected, you might run software that asks you for a public key, which could be
// AN ENTIRELY DIFFERENT PUBLIC KEY. THAT is where, metaphorically, your Public Key / User ID comes into play.






int main (int argc, char **argv) 
{
	OTLog::vOutput(0, "\n\nWelcome to Open Transactions... Test Client -- version %s\n"
				   "(transport build: OTMessage -> TCP -> SSL)\n"
				   "IF YOU PREFER TO USE XmlRpc with HTTP, then rebuild from main folder like this:\n"
				   "cd ..; make clean; make rpc\n\n", 
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

	
	
	// ------------------------------------------------------------------------------
	
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
	
	OTLog::Output(0, "You may wish to 'load' then 'connect' then 'stat'.\n");
	OTLog::vOutput(4, "Starting client loop. u_header size in C code is %d.\n", OT_CMD_HEADER_SIZE);
	
	
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
			else {
				OTLog::Output(0, "Failed trying to issue the cheque!\n");
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
		
		else if (strLine.compare(0,4,"quit") == 0)
		{
			OTLog::Output(0, "User has instructed to exit the wallet...\n");
						
			break;
		}
		
		// 1.6 Connect to the first server in the wallet. (assuming it loaded a server contract.)
		else if (strLine.compare(0,7,"connect") == 0)
		{
			OTLog::Output(0, "User has instructed to connect to the first server available in the wallet.\n");
						
			if (NULL == g_pTemporaryNym)
			{
				OTLog::Output(0, "No Nym yet available to connect with. Try 'load'.\n");
				continue;
			}
			
			// Wallet, after loading, should contain a list of server
			// contracts. Let's pull the hostname and port out of
			// the first contract, and connect to that server.
			bool bConnected = g_OT_API.GetClient()->ConnectToTheFirstServerOnList(*g_pTemporaryNym, strCAFile, strKeyFile, strSSLPassword); 
			
			if (bConnected)
				OTLog::Output(0, "Success. (Connected to the first notary server on your wallet's list.)\n");
			else {
				OTLog::Output(0, "Either the wallet is not loaded, or there was an error connecting to server.\n");
			}

			continue;
		}
		
		if (!g_OT_API.GetClient()->IsConnected())
		{
			OTLog::Output(0, "(You are not connected to a notary server--you cannot send commands.)\n");
			continue;
		}
			
		// 2) Process it out as an OTMessage to the server. It goes down the pipe.
		g_OT_API.GetClient()->ProcessMessageOut(buf, &nExpectResponse);
		
		// 3) Sleep for 1 second.
#ifdef _WIN32
		OT_Sleep(1000);
#else
		sleep (1);
#endif

		bool bFoundMessage = false;

		// 4) While there are messages to be read in response from the server,
		//	  then process and handle them all.
		do 
		{
			OTMessage * pMsg = new OTMessage;
			
			OT_ASSERT(NULL != pMsg);
			
			// If this returns true, that means a Message was
			// received and processed into an OTMessage object (theMsg)
			bFoundMessage = g_OT_API.GetClient()->ProcessInBuffer(*pMsg);
			
			if (true == bFoundMessage)
			{
//				OTString strReply;
//				theMsg.SaveContract(strReply);
//				OTLog::vOutput(0, "\n\n**********************************************\n"
//						"Successfully in-processed server response.\n\n%s\n", strReply.Get());
				g_OT_API.GetClient()->ProcessServerReply(*pMsg); // the Client takes ownership and will handle cleanup.
			}
			else 
			{
				delete pMsg;
				pMsg = NULL;
			}

		
		} while (true == bFoundMessage);
	} // for
	
	OTLog::Output(0, "Finished running client.\n");

#ifdef _WIN32
	WSACleanup();
#endif

	return retVal;
}











































