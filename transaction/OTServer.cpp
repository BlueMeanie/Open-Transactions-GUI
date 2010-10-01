/************************************************************************************
 *    
 *  OTServer.cpp
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


#include <cstdio>
#include <cstring>
#include <ctime>

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>

#include "irrxml/irrXML.h"

using namespace irr;
using namespace io;
using namespace std;


#include "OTServer.h"

#include "OTData.h"
#include "OTString.h"
#include "OTStringXML.h"

#include "OTDataCheck.h"

#include "OTMint.h"
#include "OTPseudonym.h"
#include "OTCheque.h"

#include "OTPayload.h"
#include "OTMessage.h"
#include "OTAccount.h"
#include "OTClientConnection.h"
#include "OTAssetContract.h"

#include "OTItem.h"
#include "OTTransaction.h"
#include "OTLedger.h"
#include "OTToken.h"
#include "OTPurse.h"
#include "OTBasket.h"
#include "OTLog.h"


const OTPseudonym & OTServer::GetServerNym() const
{
	return m_nymServer;
}

// Server stores a map of BASKET_ID to BASKET_ACCOUNT_ID.
bool OTServer::AddBasketAccountID(const OTIdentifier & BASKET_ID, const OTIdentifier & BASKET_ACCOUNT_ID, 
								  const OTIdentifier & BASKET_CONTRACT_ID)
{
	OTIdentifier theBasketAcctID;
	
	if (LookupBasketAccountID(BASKET_ID, theBasketAcctID))
	{
		OTLog::Output(0, "User attempted to add Basket that already exists.\n");
		return false;
	}
	
	OTString strBasketID(BASKET_ID), strBasketAcctID(BASKET_ACCOUNT_ID), strBasketContractID(BASKET_CONTRACT_ID);
	
	m_mapBaskets[strBasketID.Get()]					= strBasketAcctID.Get();
	m_mapBasketContracts[strBasketContractID.Get()]	= strBasketAcctID.Get();

	return true;
}

// Looks up a basket account ID and returns true or false.
// (So you can confirm whether or not it's on the list.)
bool OTServer::VerifyBasketAccountID(const OTIdentifier & BASKET_ACCOUNT_ID)
{
	// Server stores a map of BASKET_ID to BASKET_ACCOUNT_ID. Let's iterate through that map...
	for (mapOfBaskets::iterator ii = m_mapBaskets.begin(); ii != m_mapBaskets.end(); ++ii)
	{
		OTString strBasketAcctID	= (*ii).second.c_str();
		
		OTIdentifier id_BASKET_ACCT(strBasketAcctID);
		
		if (BASKET_ACCOUNT_ID == id_BASKET_ACCT) // if the basket Acct ID passed in matches this one...
		{
			return true;
		}
	}
	return false;
}

// Use this to find the basket account ID for this server (which is unique to this server)
// using the contract ID to look it up. (The basket contract ID is unique to this server.)
bool OTServer::LookupBasketAccountIDByContractID(const OTIdentifier & BASKET_CONTRACT_ID, OTIdentifier & BASKET_ACCOUNT_ID)
{
	// Server stores a map of BASKET_ID to BASKET_ACCOUNT_ID. Let's iterate through that map...
	for (mapOfBaskets::iterator ii = m_mapBasketContracts.begin(); ii != m_mapBasketContracts.end(); ++ii)
	{
		OTString strBasketContractID	= (*ii).first.c_str();
		OTString strBasketAcctID		= (*ii).second.c_str();
		
		OTIdentifier id_BASKET_CONTRACT(strBasketContractID), id_BASKET_ACCT(strBasketAcctID);
		
		if (BASKET_CONTRACT_ID == id_BASKET_CONTRACT) // if the basket contract ID passed in matches this one...
		{
			BASKET_ACCOUNT_ID = id_BASKET_ACCT;
			return true;
		}
	}
	return false;
}


// Use this to find the basket account ID for this server (which is unique to this server)
// using the contract ID to look it up. (The basket contract ID is unique to this server.)
bool OTServer::LookupBasketContractIDByAccountID(const OTIdentifier & BASKET_ACCOUNT_ID, OTIdentifier & BASKET_CONTRACT_ID)
{
	// Server stores a map of BASKET_ID to BASKET_ACCOUNT_ID. Let's iterate through that map...
	for (mapOfBaskets::iterator ii = m_mapBasketContracts.begin(); ii != m_mapBasketContracts.end(); ++ii)
	{
		OTString strBasketContractID	= (*ii).first.c_str();
		OTString strBasketAcctID		= (*ii).second.c_str();
		
		OTIdentifier id_BASKET_CONTRACT(strBasketContractID), id_BASKET_ACCT(strBasketAcctID);
		
		if (BASKET_ACCOUNT_ID == id_BASKET_ACCT) // if the basket contract ID passed in matches this one...
		{
			BASKET_CONTRACT_ID = id_BASKET_CONTRACT;
			return true;
		}
	}
	return false;
}


// Use this to find the basket account for this server (which is unique to this server)
// using the basket ID to look it up (the Basket ID is the same for all servers)
bool OTServer::LookupBasketAccountID(const OTIdentifier & BASKET_ID, OTIdentifier & BASKET_ACCOUNT_ID)
{
	// Server stores a map of BASKET_ID to BASKET_ACCOUNT_ID. Let's iterate through that map...
	for (mapOfBaskets::iterator ii = m_mapBaskets.begin(); ii != m_mapBaskets.end(); ++ii)
	{
		OTString strBasketID		= (*ii).first.c_str();
		OTString strBasketAcctID	= (*ii).second.c_str();
		
		OTIdentifier id_BASKET(strBasketID), id_BASKET_ACCT(strBasketAcctID);
		
		if (BASKET_ID == id_BASKET) // if the basket ID passed in matches this one...
		{
			BASKET_ACCOUNT_ID = id_BASKET_ACCT;
			return true;
		}
	}
	return false;
}


// Looked up the voucher account (where cashier's cheques are issued for any given asset type)
// return a pointer to the account.  Since it's SUPPOSED to exist, and since it's being requested,
// also will GENERATE it if it cannot be found, add it to the list, and return the pointer. Should
// always succeed.
OTAccount * OTServer::GetVoucherAccount(const OTIdentifier & ASSET_TYPE_ID)
{
	OTAccount * pAccount = NULL;
	
	for (mapOfAccounts::iterator ii = m_mapVoucherAccounts.begin(); ii != m_mapVoucherAccounts.end(); ++ii)
	{
		pAccount = (*ii).second;
		
		OT_ASSERT_MSG(NULL != pAccount, "NULL account pointer in OTServer::GetVoucherAccount");
		
		if (ASSET_TYPE_ID == pAccount->GetAssetTypeID())
			return pAccount;
	}
	

	// If we made it down here, that means the voucher account wasn't on the list,
	// so we need to create it.
	
	const OTIdentifier SERVER_USER_ID(m_nymServer), SERVER_ID(m_strServerID);
	
	OTMessage theMessage;
	SERVER_USER_ID.GetString(theMessage.m_strNymID);
	ASSET_TYPE_ID.GetString(theMessage.m_strAssetID);
	SERVER_ID.GetString(theMessage.m_strServerID);
	
	pAccount = OTAccount::GenerateNewAccount(SERVER_USER_ID, SERVER_ID, m_nymServer, theMessage);
	
	if (NULL != pAccount)
	{
		OTString strAcctID;
		pAccount->GetIdentifier(strAcctID);

		OTLog::vOutput(0, "Successfully created voucher account ID:\n%s\nAsset Type ID:\n%s\n", 
				 strAcctID.Get(), theMessage.m_strAssetID.Get());
		

		if (false == SaveMainFile())
		{
			OTLog::Error("Error saving main server file containing new account ID!!\n");
			delete pAccount;
			pAccount = NULL;
		}
		else
		{
			// Add it to the server's list.
			m_mapVoucherAccounts[theMessage.m_strAssetID.Get()] = pAccount;
		}
		
		return pAccount;
	}
	else 
	{
		OTLog::vError("Failed trying to generate voucher account in OTServer::GetVoucherAccount with asset type ID: %s\n",
				theMessage.m_strAssetID.Get());
	}
	
	return NULL;
}
	

// Lookup the current mint for any given asset type ID and series.
OTMint * OTServer::GetMint(const OTIdentifier & ASSET_TYPE_ID, int nSeries) // Each asset contract has its own Mint.
{
	OTMint * pMint = NULL;
	
	for (mapOfMints::iterator ii = m_mapMints.begin(); ii != m_mapMints.end(); ++ii)
	{
		pMint = (*ii).second;
		
		OT_ASSERT_MSG(NULL != pMint, "NULL mint pointer in  OTServer::GetMint\n");
		
		OTIdentifier theID;
		pMint->GetIdentifier(theID);
		
		if (ASSET_TYPE_ID	== theID &&				// if the ID on the Mint matches the ID passed in
			nSeries			== pMint->GetSeries())	// and the series also matches...
			return pMint;							// return the pointer right here, we're done.
	}
	
	
	// The mint isn't in memory for the series requested.
	OTString strMintPath, ASSET_ID_STR(ASSET_TYPE_ID);
	strMintPath.Format("mints/%s.%d", ASSET_ID_STR.Get(), nSeries);
	pMint = new OTMint(ASSET_ID_STR.Get(), strMintPath, ASSET_ID_STR.Get());

	// You cannot hash the Mint to get its ID. (The ID is a hash of the asset contract.)
	// Instead, you must READ the ID from the Mint file, and then compare it to the one expected
	// to see if they match (similar to how Account IDs are verified.)

	OT_ASSERT_MSG(NULL != pMint, "Error allocating memory for Mint in OTServer::GetMint");


	if (pMint->LoadContract())
	{
		if (pMint->VerifyMint(m_nymServer)) // I don't verify the Mint's expiration date here, just its signature, ID, etc.
		{									// (Expiry dates are enforced on tokens during deposit--and checked against mint-- 
											// but expiry dates are only enforced on the Mint itself during a withdrawal.)
			// It's a multimap now...
			//m_mapMints[ASSET_ID_STR.Get()] = pMint;
			m_mapMints.insert ( pair<std::string, OTMint *>(ASSET_ID_STR.Get(), pMint) );
			
			return pMint;
		}
		else 
		{
			OTLog::vError("Error verifying Mint in OTServer::GetMint:\n%s\n", strMintPath.Get());
			delete pMint;
			pMint = NULL;
		}
	}
	else 
	{
		OTLog::vError("Error loading Mint in OTServer::GetMint:\n%s\n", strMintPath.Get());
		delete pMint;
		pMint = NULL;
	}

	return NULL;
}


// Just as every request must be accompanied by a request number, so
// every transaction request must be accompanied by a transaction number.
// The request numbers can simply be incremented on both sides (per user.)
// But the transaction numbers must be issued by the server and they do
// not repeat from user to user. They are unique to transaction.
//
// Users must ask the server to send them transaction numbers so that they
// can be used in transaction requests. The server keeps an internal counter
// and maintains a data file to store the latest one.
//
// More specifically, the server file itself stores the latest transaction number
// (So it knows what number to issue and increment when the next request comes in.)
//
// But once it issues the next number, that number needs to be recorded in the nym file
// for the user it was issued to, so that it can be verified later when he submits it
// for a transaction--and so it can be removed once the transaction is complete (so it
// won't work twice.)
// 
// The option to bSaveTheNumber defaults to true for this reason. But sometimes it
// will be sent to false, in cases where the number doesn't need to be saved because
// it's never going to be verified. For example, if the server creates a transaction
// number so it can put a transaction into your inbox, it's never going to have to verify
// that it actually put it into the inbox by checking it's own nymfile for that transaction
// number. Instead it would just check its own server signature on the inbox. But I digress...
//
bool OTServer::IssueNextTransactionNumber(OTPseudonym & theNym, long &lTransactionNumber,
										  bool bStoreTheNumber/*=true*/)
{
	OTIdentifier NYM_ID(theNym), SERVER_NYM_ID(m_nymServer);
	
	// If theNym has the same ID as m_nymServer, then we'll use m_nymServer
	// instead of theNym.  (Since it's the same nym anyway, we'll stick to the
	// one we already loaded so any changes don't get overwritten later.)
	OTPseudonym * pNym = NULL;
	
	if (NYM_ID == SERVER_NYM_ID)
		pNym = &m_nymServer;
	else
		pNym = &theNym;
	
	// ----------------------------------------------------------------------------
	
	// m_lTransactionNumber stores the last VALID AND ISSUED transaction number.
	// So first, we increment that, since we don't want to issue the same number twice.
	m_lTransactionNumber++;
	
	// Next, we save it to file.
	if (false == SaveMainFile())
	{
		OTLog::Error("Error saving main server file.\n");
		m_lTransactionNumber--;
		return false;
	}
	
	// Each Nym stores the transaction numbers that have been issued to it.
	// (On client AND server side.)
	//
	// So whenever the server issues a new number, it's to a specific Nym, then
	// it is recorded in his Nym file before being sent to the client (where it
	// is also recorded in his Nym file.)  That way the server always knows which
	// numbers are valid for each Nym.
	
	else if ( bStoreTheNumber && 
			 (false == pNym->AddTransactionNum(m_nymServer, m_strServerID, m_lTransactionNumber, true))) // bSave = true
	{
		OTLog::Error("Error adding transaction number to Nym file.\n");
		m_lTransactionNumber--;
		SaveMainFile(); // Save it back how it was, since we're not issuing this number after all.
		return false;
	}
	
	// SUCCESS? 
	// Now the server main file has saved the latest transaction number,
	// and the number has been stored on the relevant nym file.
	// NOW we set it onto the parameter and return true.
	else 
	{  
		lTransactionNumber = m_lTransactionNumber;
		return true;		
	}
}



// Transaction numbers are now stored in the nym file (on client and server side) for whichever nym
// they were issued to. This function verifies whether or not the transaction number is present and valid
// for any specific nym (i.e. for the nym passed in.)
bool OTServer::VerifyTransactionNumber(OTPseudonym & theNym, const long &lTransactionNumber) // passed by reference for speed, but not a return value.
{
	OTIdentifier NYM_ID(theNym), SERVER_NYM_ID(m_nymServer);
	
	// If theNym has the same ID as m_nymServer, then we'll use m_nymServer
	// instead of theNym.  (Since it's the same nym anyway, we'll stick to the
	// one we already loaded so any changes don't get overwritten later.)
	OTPseudonym * pNym = NULL;
	
	if (NYM_ID == SERVER_NYM_ID)
		pNym = &m_nymServer;
	else
		pNym = &theNym;

	
	if (pNym->VerifyTransactionNum(m_strServerID, lTransactionNumber))
		return true;
	else {
		OTLog::vError("Invalid transaction number: %ld.  (Current Trns# counter: %ld)\n", 
				lTransactionNumber, m_lTransactionNumber);
		return false;
	}
}


// Remove a transaction number from the Nym record once it's officially used/spent.
bool OTServer::RemoveTransactionNumber(OTPseudonym & theNym, const long &lTransactionNumber)
{
	OTIdentifier NYM_ID(theNym), SERVER_NYM_ID(m_nymServer);

	// If theNym has the same ID as m_nymServer, then we'll use m_nymServer
	// instead of theNym.  (Since it's the same nym anyway, we'll stick to the
	// one we already loaded so any changes don't get overwritten later.)
	OTPseudonym * pNym = NULL;
	
	if (NYM_ID == SERVER_NYM_ID)
		pNym = &m_nymServer;
	else
		pNym = &theNym;

	return pNym->RemoveTransactionNum(m_nymServer, m_strServerID, lTransactionNumber);
}



// The server supports various different asset types.
// Any user may create a new asset type by uploading the asset contract to the server.
// The server stores the contract in a directory and in its in-memory list of asset types.
// You can call this function to look up any asset contract by ID. If it returns NULL,
// you can add it yourself by uploading the contract.  But be sure that the public key
// in the contract, used to sign the contract, is also the public key of the Nym of the
// issuer.  They must match.  In the future I may create a special key category just for
// this purpose. Right now I'm using the "contract" key which is already used to verify
// any asset or server contract.
OTAssetContract * OTServer::GetAssetContract(const OTIdentifier & ASSET_TYPE_ID)
{
	OTAssetContract * pContract = NULL;
	
	for (mapOfContracts::iterator ii = m_mapContracts.begin(); ii != m_mapContracts.end(); ++ii)
	{
		if (pContract = (*ii).second) // if not null
		{
			OTIdentifier theContractID;
			pContract->GetIdentifier(theContractID);
			
			if (theContractID == ASSET_TYPE_ID)
				return pContract;
		}
		else 
		{
			OTLog::Error("NULL contract pointer in OTServer::GetAssetContract.\n");
		}
	}
	
	return NULL;
}

// OTServer will take ownership of theContract from this point on,
// and will be responsible for deleting it. MUST be allocated on the heap.
bool OTServer::AddAssetContract(OTAssetContract & theContract)
{
	OTAssetContract * pContract = NULL;
	
	OTString STR_CONTRACT_ID; OTIdentifier CONTRACT_ID;
	theContract.GetIdentifier(STR_CONTRACT_ID);
	theContract.GetIdentifier(CONTRACT_ID);
	
	// already exists
	if (pContract = GetAssetContract(CONTRACT_ID)) // if not null
		return false;
	
	m_mapContracts[STR_CONTRACT_ID.Get()] = &theContract;
	
	return true;
}


bool OTServer::SaveMainFile()
{
	static OTString strMainFilePath;
	
	if (!strMainFilePath.Exists())
	{
		strMainFilePath.Format(
#ifdef _WIN32 
		"%s%snotaryServer-Windows.xml", // todo fix hardcoding
#else
                "%s%snotaryServer.xml", // todo fix hardcoding
#endif
		OTLog::Path(), OTLog::PathSeparator());
	}

	
	std::ofstream ofs(strMainFilePath.Get(), std::ios::binary);

/*
#ifdef _WIN32
	errno_t err;
	FILE * fl;
	err = fopen_s(&fl, strMainFilePath.Get(), "wb");
#else
	FILE * fl = fopen(strMainFilePath.Get(), "w");
#endif

	if (NULL == fl)
	{
		OTLog::vError("Error opening file in OTServer::SaveMainFile: %s\n", strMainFilePath.Get());
		return false;
	}
*/
	
	if (ofs.fail())
	{
		OTLog::vError("Error opening file in OTServer::SaveMainFile: %s\n", strMainFilePath.Get());
		return false;
	}	
	ofs.clear();
	
	// ---------------------------------------------------------------
	
	ofs << "<?xml version=\"1.0\"?>\n"
	"<notaryServer version=\"" << m_strVersion.Get() << "\"\n"
	" serverID=\"" << m_strServerID.Get() << "\"\n"
	" serverUserID=\"" << m_strServerUserID.Get() << "\"\n"
	" transactionNum=\"" << m_lTransactionNumber << "\" >\n\n";
	
	//mapOfContracts	m_mapContracts;   // If the server needs to store copies of the asset contracts, then here they are.
	//mapOfMints		m_mapMints;		  // Mints for each of those.
	
	// ---------------------------------------------------------------
	
	OTContract * pContract = NULL;
	
	for (mapOfContracts::iterator ii = m_mapContracts.begin(); ii != m_mapContracts.end(); ++ii)
	{
		pContract = (*ii).second;
		
		OT_ASSERT_MSG(NULL != pContract, "NULL contract pointer in OTServer::SaveMainFile.\n");
	
		// This is like the Server's wallet.
		pContract->SaveContractWallet(ofs);
		
		// ----------------------------------------
	}
	
	// Save the basket account information
	
	for (mapOfBaskets::iterator ii = m_mapBaskets.begin(); ii != m_mapBaskets.end(); ++ii)
	{
		OTString strBasketID		= (*ii).first.c_str();
		OTString strBasketAcctID	= (*ii).second.c_str();
		
		const	OTIdentifier BASKET_ACCOUNT_ID(strBasketAcctID);
				OTIdentifier BASKET_CONTRACT_ID;
		
		bool bContractID = LookupBasketContractIDByAccountID(BASKET_ACCOUNT_ID, BASKET_CONTRACT_ID);
		
		if (!bContractID)
		{
			OTLog::vError("Error in OTServer::SaveMainFile: Missing Contract ID for basket ID %s\n",
					strBasketID.Get());
			break;
		}
		
		OTString strBasketContractID(BASKET_CONTRACT_ID);
		
		ofs << "<basketInfo basketID=\"" << strBasketID.Get() << "\"\n basketAcctID=\"" << strBasketAcctID.Get() << 
		"\"\n basketContractID=\"" << strBasketContractID.Get() << "\" />\n\n";
	}
	
	/*
	OTPseudonym * pNym = NULL;
	
	for (mapOfNyms::iterator ii = m_mapNyms.begin(); ii != m_mapNyms.end(); ++ii)
	{		
		pNym = (*ii).second;
	 
		OT_ASSERT_MSG(NULL != pNym, "NULL pseudonym pointer in OTWallet::m_mapNyms, OTWallet::SaveWallet");
		
		pNym->SavePseudonymWallet(fl);
	}
	
	
	// ---------------------------------------------------------------
	
	OTContract * pServer = NULL;
	
	for (mapOfServers::iterator ii = m_mapServers.begin(); ii != m_mapServers.end(); ++ii)
	{
		pServer = (*ii).second;
	 
		OT_ASSERT_MSG(NULL != pServer, "NULL server pointer in OTWallet::m_mapServers, OTWallet::SaveWallet");
	 
		pServer->SaveContractWallet(fl);
	}
	
	// ---------------------------------------------------------------
	 */

	
	ofs << "</notaryServer>\n" << endl;
	
	ofs.close();
	
	return true;
}




// Currently stores only the latest transaction number.
bool OTServer::LoadMainFile()
{
	static OTString strMainFilePath;
	
	if (!strMainFilePath.Exists())
	{
		strMainFilePath.Format(
#ifdef _WIN32
			"%s%snotaryServer-Windows.xml",
#else 
                        "%s%snotaryServer.xml", 
#endif
			OTLog::Path(), OTLog::PathSeparator());
	}
	
	
	OTStringXML xmlFileContents;
	
	
	std::ifstream in(strMainFilePath.Get(), std::ios::binary);
	
	if (in.fail())
	{
		OTLog::vError("Error opening main file: %s\n", strMainFilePath.Get());
		return false;		
	}
	
	std::stringstream buffer;
	buffer << in.rdbuf();
	
	std::string contents(buffer.str());
	
	xmlFileContents.Set(contents.c_str());
	
	if (xmlFileContents.GetLength() < 2)
	{
		OTLog::vError("Error reading main file: %s\n", strMainFilePath.Get());
		return false;
	}
	
	
	IrrXMLReader* xml = createIrrXMLReader(&xmlFileContents);
	
	// parse the file until end reached
	while(xml && xml->read())
	{
		// strings for storing the data that we want to read out of the file
		
		OTString AssetName;
		OTString AssetContract;
		OTString AssetID;
		/*
		OTString NymName;
		OTString NymFile;
		OTString NymID;
		
		
		OTString ServerName;
		OTString ServerContract;
		OTString ServerID;
		*/
		
		switch(xml->getNodeType())
		{
			case EXN_TEXT:
				// in this xml file, the only text which occurs is the messageText
				//messageText = xml->getNodeData();
				break;
			case EXN_ELEMENT:
			{
				if (!strcmp("notaryServer", xml->getNodeName()))
				{
					m_strVersion			= xml->getAttributeValue("version");					
					m_strServerID			= xml->getAttributeValue("serverID");
					m_strServerUserID		= xml->getAttributeValue("serverUserID");
					
					m_nymServer.SetIdentifier(m_strServerUserID);
					
					if (!m_nymServer.Loadx509CertAndPrivateKey())
					{
						OTLog::Output(0, "Error loading server certificate and keys.\n");
					}
					if (!m_nymServer.VerifyPseudonym())
					{
						OTLog::Output(0, "Error verifying server nym.\n");
					}
					else {
						// This file will be saved during the course of operation
						// Just making sure it is loaded up first.
						// Todo: exit() if this fails.
						m_nymServer.LoadSignedNymfile(m_nymServer);
						
					//	m_nymServer.SaveSignedNymfile(m_nymServer); // Uncomment this if you want to create the file. NORMALLY LEAVE IT OUT!!!! DANGEROUS!!!
						
						OTLog::Output(0, "Success loading server certificate and keys.\n");
					}
					
					OTString strTransactionNumber;
					strTransactionNumber	= xml->getAttributeValue("transactionNum");
					m_lTransactionNumber	= atol(strTransactionNumber.Get());
					
					OTLog::vOutput(0, "\nLoading Open Transactions server. File version: %s\nLast Issued Transaction Number: %ld\nServerID:\n%s\n", 
							m_strVersion.Get(), m_lTransactionNumber, m_strServerID.Get());
				}
				else if (!strcmp("basketInfo", xml->getNodeName()))
				{
					OTString strBasketID			= xml->getAttributeValue("basketID");					
					OTString strBasketAcctID		= xml->getAttributeValue("basketAcctID");
					OTString strBasketContractID	= xml->getAttributeValue("basketContractID");
					
					const OTIdentifier BASKET_ID(strBasketID), BASKET_ACCT_ID(strBasketAcctID), BASKET_CONTRACT_ID(strBasketContractID);
					
					if (AddBasketAccountID(BASKET_ID, BASKET_ACCT_ID, BASKET_CONTRACT_ID))						
						OTLog::vOutput(0, "Loading basket currency info...\n Basket ID:\n%s\n Basket Acct ID:\n%s\n Basket Contract ID:\n%s\n", 
								strBasketID.Get(), strBasketAcctID.Get(), strBasketContractID.Get());
					else						
						OTLog::vError("Error adding basket currency info...\n Basket ID:\n%s\n Basket Acct ID:\n%s\n", 
								strBasketID.Get(), strBasketAcctID.Get());
				}

				// Create an OTMint and an OTAssetContract and load them from file, (for each asset type),
				// and add them to the internal map.
				else if (!strcmp("assetType", xml->getNodeName()))
				{
					AssetName		= xml->getAttributeValue("name");			
					AssetID			= xml->getAttributeValue("assetTypeID");	// hash of contract itself
					
					OTLog::vOutput(0, "\n\n****Asset Contract**** (server listing) Name: %s\nContract ID:\n%s\n",
							AssetName.Get(), AssetID.Get());
					
					OTString strContractPath;
					strContractPath.Format("%s%scontracts%s%s", OTLog::Path(), OTLog::PathSeparator(),
										   OTLog::PathSeparator(), AssetID.Get());
					OTAssetContract * pContract = new OTAssetContract(AssetName, strContractPath, AssetID);
					
					OT_ASSERT_MSG(NULL != pContract, "Error allocating memory for Asset Contract in OTServer::LoadMainFile\n");
					
					if (pContract->LoadContract()) 
					{
						if (pContract->VerifyContract())
						{
							OTLog::Output(0, "** Asset Contract Verified **\n");
							
							m_mapContracts[AssetID.Get()] = pContract;
						}
						else
						{
							OTLog::Output(0, "Asset Contract FAILED to verify.\n");
						}							
					}
					else 
					{
						OTLog::Output(0, "Failed reading file for Asset Contract in OTServer::LoadMainFile\n");
					}
				}
				/*
				 // commented out because, since I already have the serverID, then the server
				 // already knows which certfile to open in order to get at its private key.
				 // So I already have the private key loaded, so I don't need pseudonyms in
				 // the config file right now.
				 //
				 // In the future, I will load the server XML file (here) FIRST, and get the serverID and
				 // contract file from that. THEN I will hash the contract file and verify that it matches
				 // the serverID. THEN I will use that serverID to open the Certfile and get my private key.
				 //
				 // In the meantime I don't need this yet, serverID is hardcoded in the constructor already.
				else if (!strcmp("pseudonym", xml->getNodeName())) // The server has to sign things, too.
				{
					NymName = xml->getAttributeValue("name");// user-assigned name for GUI usage				
					NymID = xml->getAttributeValue("nymID"); // message digest from hash of x.509 cert, used to look up certfile.
					
					OTLog::vOutput(0, "\n\n** Pseudonym ** (server): %s\nID: %s\nfile: %s\n",
							NymName.Get(), NymID.Get(), NymFile.Get());
					
					OTPseudonym * pNym = new OTPseudonym(NymName, NymFile, NymID);
					
					if (pNym && pNym->LoadNymfile((char*)(NymFile.Get())))
					{
						if (pNym->Loadx509CertAndPrivateKey()) 
						{							
							if (pNym->VerifyPseudonym()) 
							{
								m_mapNyms[NymID.Get()] = pNym;
								g_pTemporaryNym = pNym; // TODO remove this temporary line used for testing only.
							}
							else {
								OTLog::Error("Error verifying public key from x509 against Nym ID in OTWallet::LoadWallet\n");
							}
						}
						else {
							OTLog::Error("Error loading x509 file for Pseudonym in OTWallet::LoadWallet\n");
						}
					}
					else {
						OTLog::Error("Error creating or loading Nym in OTWallet::LoadWallet\n");
					}
				}
				 
				 // Don't need this (yet)
				else if (!strcmp("assetType", xml->getNodeName()))
				{
					AssetName = xml->getAttributeValue("name");			
					AssetContract = xml->getAttributeValue("contract"); // digital asset contract file
					AssetID = xml->getAttributeValue("assetTypeID"); // hash of contract itself
					
					OTLog::vOutput(0, "\n\n****Asset Contract**** (wallet listing) Name: %s\nContract ID:\n%s"
							"\nLocation of contract file: %s\n",
							AssetName.Get(), AssetID.Get(), AssetContract.Get());
					
					OTAssetContract * pContract = new OTAssetContract(AssetName, AssetContract, AssetID);
					
					if (pContract)
					{
						if (pContract->LoadContract()) 
						{
							if (pContract->VerifyContract())
							{
								OTLog::vOutput(0, "** Asset Contract Verified **\n");
								
								m_mapContracts[AssetID.Get()] = pContract;
								g_pTemporaryContract = pContract; // TODO remove this temporary line used for testing only
							}
							else
							{
								OTLog::Error("Contract FAILED to verify.\n");
							}							
						}
						else {
							OTLog::Error("Error reading file for Asset Contract in OTWallet::LoadWallet\n");
						}
					}
					else {
						OTLog::Error("Error allocating memory for Asset Contract in OTWallet::LoadWallet\n");
					}
				}
				 
				 // This is where the server finds out his own contract, which he hashes in order to verify his
				 // serverID (which is either hardcoded or stored in the server xml file.)
				 //
				 // There should be only one of these per transaction server.
				 //
				 // Commented out because I don't need it right now. TODO.
				 //
				else if (!strcmp("notaryProvider", xml->getNodeName())) 
				{
					ServerName = xml->getAttributeValue("name");					
					ServerContract = xml->getAttributeValue("contract"); // transaction server contract
					ServerID = xml->getAttributeValue("serverID"); // hash of contract
					
					OTLog::vOutput(0, "\n\n\n****Notary Server (contract)**** (wallet listing): %s\n ServerID:\n%s\n"
							"contract file: %s\n", ServerName.Get(), ServerID.Get(), ServerContract.Get());
					
					OTServerContract * pContract = new OTServerContract(ServerName, ServerContract, ServerID);
					
					if (pContract)
					{
						if (pContract->LoadContract()) 
						{
							// TODO: move these lines back into the 'if' block below.
							// Moved them temporarily so I could regenerate some newly-signed contracts
							// for testing only.
							m_mapServers[ServerID.Get()] = pContract;
							g_pServerContract = pContract; // TODO remove this temporary line used for testing only
							
							if (pContract->VerifyContract())
							{
								OTLog::Output(0, "** Server Contract Verified **\n\n");
								
							}
							else
							{
								OTLog::Error("Server contract failed to verify.\n");
							}
						}
						else {
							OTLog::Error("Error reading file for Transaction Server in OTWallet::LoadWallet\n");
						}
					}
					else {
						OTLog::Error("Error allocating memory for Server Contract in OTWallet::LoadWallet\n");
					}
				}
				 */
				else
				{
					// unknown element type
					OTLog::vError("unknown element type: %s\n", xml->getNodeName());
				}
			}
				break;
		}
	}
	
	
	// delete the xml parser after usage
	if (xml)
		delete xml;
	
	return true;
	
}


/*
 (<bankid>,@register,(<id2>,register,<bankid>,<pubkey>,name=<name>))
 
 If there is no such id, bank responds with:
 
 (<bankid>,failed,(<id>,id,<bankid>,<id2>),errcode:<errcode>,reason:<reason>)
 
 Note that only registered customers can ask for another customer's
 public key. Otherwise, the bank won't know the public key with which
 to validate the request. Also note that this request can be replayed.
 The response is always the same, so what's the harm?
 */


void OTServer::UserCmdCheckServerID(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	// (1) set up member variables 
	msgOut.m_strCommand		= "@checkServerID";	// reply to checkServerID
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	
	if (MsgIn.m_strServerID == m_strServerID)	// ServerID, a hash of the server contract.
		msgOut.m_bSuccess		= true;
	else
		msgOut.m_bSuccess		= false;
	
	// (2) Sign the Message 
	msgOut.SignContract(m_nymServer);		
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();
}



void OTServer::UserCmdGetTransactionNum(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	long lTransNum = 0;
	
	// (1) set up member variables 
	msgOut.m_strCommand		= "@getTransactionNum";	// reply to getTransactionNum
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	
	// This call will save the new transaction number to the nym's file.
	msgOut.m_bSuccess	= IssueNextTransactionNumber(theNym, lTransNum);
	
	if (!msgOut.m_bSuccess)
	{
		lTransNum = 0;
		OTLog::Error("Error getting next transaction number in OTServer::UserCmdGetTransactionNum\n");
	}
	// But we still need to bundle it up and send it to him, so he can save
	// it into his nymfile on the client side as well.
	else {
		OTPseudonym theMessageNym;
		theMessageNym.AddTransactionNum(m_strServerID, lTransNum); // this version of AddTransactionNum won't bother saving to file.
		
		OTString strMessageNym(theMessageNym);
		
		msgOut.m_ascPayload.SetString(strMessageNym, true); // linebreaks = true
	}
	
	// (2) Sign the Message 
	msgOut.SignContract(m_nymServer);		
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();	
}

void OTServer::UserCmdGetRequest(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	long lReqNum = 0;
	
	// (1) set up member variables 
	msgOut.m_strCommand		= "@getRequest";	// reply to getRequest
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	
	msgOut.m_bSuccess	= theNym.GetCurrentRequestNum(m_strServerID, lReqNum);
	
	// Server was unable to load ReqNum, which is unusual because the calling function
	// should have already insured its existence.
	if (!msgOut.m_bSuccess)
	{
		lReqNum = 0;
		OTLog::Error("Error loading request number in OTServer::UserCmdGetRequest\n");
	}
	
	msgOut.m_strRequestNum.Format("%ld", lReqNum);
	
	// (2) Sign the Message 
	msgOut.SignContract(m_nymServer);		
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();
}



void OTServer::UserCmdCheckUser(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	// (1) set up member variables 
	msgOut.m_strCommand		= "@checkUser";	// reply to checkUser
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strNymID2		= MsgIn.m_strNymID2;// UserID of public key requested by user.
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.

	OTPseudonym nym2;	
	nym2.SetIdentifier(MsgIn.m_strNymID2);
		
	// If success, we send the Nym2's public key back to the user.
	if (msgOut.m_bSuccess = nym2.LoadPublicKey())
	{
		nym2.GetPublicKey().GetPublicKey(msgOut.m_strNymPublicKey, true);
	}
	// if Failed, we send the user's message back to him, ascii-armored as part of response.
	else 
	{
		OTString tempInMessage(MsgIn);
		msgOut.m_ascInReferenceTo.SetString(tempInMessage);
	}

	// (2) Sign the Message 
	msgOut.SignContract(m_nymServer);		
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();
}




// An existing user is issuing a new currency.
void OTServer::UserCmdIssueAssetType(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	// (1) set up member variables 
	msgOut.m_strCommand		= "@issueAssetType";// reply to issueAssetType
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strAssetID		= MsgIn.m_strAssetID;	// Asset Type ID, a hash of the asset contract.
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	
	const OTIdentifier USER_ID(theNym), SERVER_ID(m_strServerID), ASSET_TYPE_ID(MsgIn.m_strAssetID);
	
	OTAssetContract * pAssetContract = NULL;

	// Make sure the contract isn't already available on this server.
	if (pAssetContract = GetAssetContract(ASSET_TYPE_ID))
	{
		OTLog::Error("Error: Attempt to issue asset type that already exists in OTServer::UserCmdIssueAssetType.\n");
	}
	else
	{		
		// Pull the contract out of the message and verify it.
		OTString strFilename;
		strFilename.Format("%s%scontracts%s%s", OTLog::Path(), OTLog::PathSeparator(), 
						   OTLog::PathSeparator(), MsgIn.m_strAssetID.Get());

		OTString strContract(MsgIn.m_ascPayload);
		pAssetContract = new OTAssetContract(MsgIn.m_strAssetID, strFilename, MsgIn.m_strAssetID);
		
		OTIdentifier	ASSET_USER_ID;
		bool			bSuccessLoadingContract	= false;
		bool			bSuccessCalculateDigest = false;
		OTPseudonym *	pNym					= NULL;

		if (pAssetContract)
		{
			bSuccessLoadingContract	= pAssetContract->LoadContractFromString(strContract);
			
			if (pNym = (OTPseudonym*)pAssetContract->GetContractPublicNym())
			{
//				pNym->GetIdentifier(ASSET_USER_ID);
				OTString strPublicKey;
				bool bGotPublicKey = pNym->GetPublicKey().GetPublicKey(strPublicKey);
				
				if (!bGotPublicKey)
				{
					OTLog::Error("Error getting public key in OTServer::UserCmdIssueAssetType.\n");
				}
				else 
				{
					bSuccessCalculateDigest = ASSET_USER_ID.CalculateDigest(strPublicKey);
					
					if (!bSuccessCalculateDigest)
					{
						OTLog::Error("Error calculating digest in OTServer::UserCmdIssueAssetType.\n");
					}
				}
			}
		}
				
		// Make sure the public key in the contract is the public key of the Nym.
		// If we successfully loaded the contract from the string, and the contract
		// internally verifies (the ID matches the hash of the contract, and the
		// signature verifies with the contract key that's inside the contract),
		// AND the Nym making this request has the same ID as the Nym in the
		// asset contract. (ONLY the issuer of that contract can connect to this
		// server and issue his currency.)
		// TODO make sure a receipt is issued that the issuer can post on his
		// website, to verify that he has indeed issued the currency at the specified
		// transaction processor.  That way, users can double-check.
		if (bSuccessCalculateDigest)
		{
			if ((ASSET_USER_ID == USER_ID))
										// The ID of the user who signed the contract must be the ID of the user
										// whose public key is associated with this user account. They are one.
			{
				if (pAssetContract->VerifyContract())
				{
					// Create an ISSUER account (like a normal account, except it can go negative)
					OTAccount * pNewAccount = NULL;
					
					// If we successfully create the account, then bundle it in the message XML payload
					if (pNewAccount = OTAccount::GenerateNewAccount(USER_ID, SERVER_ID, m_nymServer, MsgIn, 
																	OTAccount::issuer)) // This last parameter makes it an ISSUER account
					{																	// instead of the default SIMPLE.
						OTString tempPayload(*pNewAccount);
						msgOut.m_ascPayload.SetString(tempPayload);
				
						// Attach the new account number to the outgoing message.
						pNewAccount->GetIdentifier(msgOut.m_strAcctID);

						// Now that the account is actually created, let's add the new asset contract
						// to the server's list.
						AddAssetContract(*pAssetContract);
						SaveMainFile(); // So the main xml file knows to load this asset type next time we run.
						
						// Make sure the contracts/%s file is created for next time.
						pAssetContract->SaveContract(strFilename.Get());
						
						// TODO fire off a separate process here to create the mint.
						
						msgOut.m_bSuccess = true;

						delete pNewAccount;
						pNewAccount = NULL;
					}
					else {
						OTLog::Error("Failure generating new issuer account in OTServer::UserCmdIssueAssetType.\n");
					}
				}
				else {
					OTLog::Error("Failure verifying asset contract in OTServer::UserCmdIssueAssetType.\n");
				}
			}
			else {
				OTString strAssetUserID(ASSET_USER_ID), strUserID;
				theNym.GetIdentifier(strUserID);
				OTLog::vError("User ID on this user account:\n%s\ndoes NOT match public key used in asset contract:\n%s\n",
						strUserID.Get(), strAssetUserID.Get());
			}
		}
		else
		{
			OTLog::Error("Failure loading asset contract from client in OTServer::UserCmdIssueAssetType\n");
		}
		
		
		if (pAssetContract && !msgOut.m_bSuccess)
		{
			delete pAssetContract;
			pAssetContract = NULL;
		}
	}

	// Either way, we need to send the user's command back to him as well.
	{
		OTString tempInMessage(MsgIn);
		msgOut.m_ascInReferenceTo.SetString(tempInMessage);
	}

	// (2) Sign the Message 
	msgOut.SignContract(m_nymServer);		 
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();
}



// Okay I think this function is done.  At least until I start testing...
// An existing user is creating an issuer account (that he will not control) based on a basket of currencies.
void OTServer::UserCmdIssueBasket(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	// (1) set up member variables 
	msgOut.m_strCommand		= "@issueBasket";	// reply to issueBasket
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	
	// Either way, we need to send the user's command back to him as well.
	{
		OTString tempInMessage(MsgIn);
		msgOut.m_ascInReferenceTo.SetString(tempInMessage);
	}
	
	const OTIdentifier USER_ID(theNym), SERVER_ID(m_strServerID), SERVER_USER_ID(m_nymServer);
	
	OTString strBasket(MsgIn.m_ascPayload);
	OTBasket theBasket;
	
	if (theBasket.LoadContractFromString(strBasket) && theBasket.VerifySignature(theNym))
	{		
		// The contract ID of the basket is calculated based on the UNSIGNED portion of the contract
		// (so it is unique on every server) and for the same reason with the AccountID removed before calculating.
		OTIdentifier BASKET_ID, BASKET_ACCOUNT_ID, BASKET_CONTRACT_ID;
		theBasket.CalculateContractID(BASKET_ID);
		
		// Use BASKET_ID to look up the Basket account and see if it already exists (the server keeps a list.)
		bool bFoundBasket = LookupBasketAccountID(BASKET_ID, BASKET_ACCOUNT_ID);
		
		if (!bFoundBasket)
		{
			// Generate a new OTAssetContract -- the ID will be a hash of THAT contract, which includes theBasket as well as
			// the server's public key as part of its contents. Therefore, the actual Asset Type ID of the basket currency
			// will be different from server to server.
			//
			// BUT!! Because we can also generate a hash of theBasket.m_xmlUnsigned (which is what OTBasket::CalculateContractID
			// does) then we have a way of obtaining a number that will be the same from server to server, for cross-server
			// transfers of basket assets.
			//
			// The way it will work is, when the cross-server transfer request is generated, the server will check the asset contract
			// for the "from" account and see if it is for a basket currency. If it is, there will be a function on the contract
			// that returns the Basket ID, which can be included in the message to the target server, which uses the ID to look
			// for its own basket issuer account for the same basket asset type. This allows the target server to translate the 
			// Asset Type ID to its own corresponding ID for the same basket.
			
			
			// GenerateNewAccount also expects the NymID to be stored in m_strNymID.
			// Since we want the SERVER to be the user for basket accounts, I'm setting it that
			// way in MsgIn so that GenerateNewAccount will create the sub-account with the server
			// as the owner, instead of the user.
			SERVER_USER_ID.GetString(MsgIn.m_strNymID);
			
			// We need to actually create all the sub-accounts.
			// This loop also sets the Account ID onto the basket items (which formerly was blank, from the client.)
			// This loop also adds the BASKET_ID and the NEW ACCOUNT ID to a map on the server for later reference.
			for (int i = 0; i < theBasket.Count(); i++)
			{
				BasketItem * pItem = theBasket.At(i);
				
				
				/*
				 
				 // Just make sure theMessage has these members populated:
				 //
				 // theMessage.m_strNymID;
				 // theMessage.m_strAssetID; 
				 // theMessage.m_strServerID;
				 
				 // static method (call it without an instance, using notation: OTAccount::GenerateNewAccount)
				 OTAccount * OTAccount::GenerateNewAccount(	const OTIdentifier & theUserID,	const OTIdentifier & theServerID, 
															const OTPseudonym & theServerNym,	const OTMessage & theMessage,
															const OTAccount::AccountType eAcctType=OTAccount::simple)

				
				 // The above method uses this one internally...
				 bool OTAccount::GenerateNewAccount(const OTPseudonym & theServer, const OTMessage & theMessage,
													const OTAccount::AccountType eAcctType=OTAccount::simple)
				 
				 */
				
				OTAccount * pNewAccount = NULL;
				
				// GenerateNewAccount expects the Asset ID to be in MsgIn. So we'll just put it there to make things easy...
				pItem->SUB_CONTRACT_ID.GetString(MsgIn.m_strAssetID);
								
				// If we successfully create the account, then bundle it in the message XML payload
				if (pNewAccount = OTAccount::GenerateNewAccount(SERVER_USER_ID, SERVER_ID, m_nymServer, MsgIn))
				{
					msgOut.m_bSuccess = true;
					
					// Now the item finally has its account ID. Let's grab it.
					pNewAccount->GetIdentifier(pItem->SUB_ACCOUNT_ID);
					
					delete pNewAccount;
					pNewAccount = NULL;
				}
				else {
					msgOut.m_bSuccess = false;
					break;
				}
			} // for
			
			
			if (true == msgOut.m_bSuccess)
			{
				theBasket.ReleaseSignatures();
				theBasket.SignContract(m_nymServer);
				theBasket.SaveContract();
				
				// The basket does not yet exist on this server. Create a new Asset Contract to support it...
				OTAssetContract * pBasketContract = new OTAssetContract;
				
				// todo check for memory allocation failure here.
				
				// Put the Server's Public Key into the "contract" key field of the new Asset Contract...
				// This adds a "contract" key to the asset contract (the server's public key)
				// Asset Contracts are verified by a key found internal to the contract, so it's
				// necessary to put the key in there so it will verify later.
				// This also updates the m_xmlUnsigned contents, signs the contract, saves it,
				// and calculates the new ID.
				pBasketContract->CreateBasket(theBasket, m_nymServer);
				
				// Grab the new asset ID for the new basket currency
				pBasketContract->GetIdentifier(BASKET_CONTRACT_ID);
				OTString STR_BASKET_CONTRACT_ID(BASKET_CONTRACT_ID);
				
				// set the new Asset Type ID, aka ContractID, onto the outgoing message.
				msgOut.m_strAssetID = STR_BASKET_CONTRACT_ID;
				
				// Save the new Asset Contract to disk
				OTString strFilename;
				strFilename.Format("%s%scontracts%s%s", OTLog::Path(), OTLog::PathSeparator(), 
								   OTLog::PathSeparator(), STR_BASKET_CONTRACT_ID.Get());
				
				// Save the new basket contract to the contracts folder 
				// (So the users can use it the same as they would use any other contract.)
				pBasketContract->SaveContract(strFilename.Get());
				
				AddAssetContract(*pBasketContract);
				// I don't save this here. Instead, I wait for AddBasketAccountID and then I call SaveMainFile after that. See below.
				// TODO need better code for reverting when something screws up halfway through a change.
				// If I add this contract, it's not enough to just "not save" the file. I actually need to re-load the file
				// in order to TRULY "make sure" this won't screw something up on down the line.
				
				// Once the new Asset Type is generated, from which the BasketID can be requested at will, next we need to create
				// the issuer account for that new Asset Type.  (We have the asset type ID and the contract file. Now let's create
				// the issuer account the same as we would for any normal issuer account.)
				//
				// The issuer account is special compared to a normal issuer account, because within its walls, it must store an
				// OTAccount for EACH sub-contract, in order to store the reserves. That's what makes the basket work.
				
				OTAccount * pBasketAccount = NULL;
				
				// GenerateNewAccount expects the Asset ID to be in MsgIn. So we'll just put it there to make things easy...
				MsgIn.m_strAssetID = STR_BASKET_CONTRACT_ID;
				
				if (pBasketAccount = OTAccount::GenerateNewAccount(SERVER_USER_ID, SERVER_ID, m_nymServer, MsgIn, OTAccount::basket))
				{			
					msgOut.m_bSuccess = true;
					
					pBasketAccount->GetIdentifier(msgOut.m_strAcctID); // string
					pBasketAccount->GetAssetTypeID().GetString(msgOut.m_strAssetID);
					
					pBasketAccount->GetIdentifier(BASKET_ACCOUNT_ID); // id
					
					// So the server can later use the BASKET_ID (which is universal)
					// to lookup the account ID on this server corresponding to that basket.
					// (The account ID will be different from server to server, thus the need
					// to be able to look it up via the basket ID.)
					AddBasketAccountID(BASKET_ID, BASKET_ACCOUNT_ID, BASKET_CONTRACT_ID);

					SaveMainFile(); // So the main xml file loads this basket info next time we run.
					
					delete pBasketAccount;
					pBasketAccount = NULL;
				}
				else {
					msgOut.m_bSuccess = false;
				}
				
			}// if true == msgOut.m_bSuccess
		}
	}
	
	// (2) Sign the Message 
	msgOut.SignContract(m_nymServer);		 
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();
}




// a user is exchanging in or out of a basket.  (Ex. He's trading 2 gold and 3 silver for 10 baskets, or vice-versa.)
void OTServer::UserCmdExchangeBasket(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	// (1) set up member variables 
	msgOut.m_strCommand		= "@exchangeBasket";// reply to exchangeBasket
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	msgOut.m_strAssetID		= MsgIn.m_strAssetID;// basket asset type ID
	msgOut.m_bBool			= MsgIn.m_bBool;	// exchange in or out?
	
	const OTIdentifier	USER_ID(theNym), SERVER_ID(m_strServerID), 
						SERVER_USER_ID(m_nymServer), 
						BASKET_CONTRACT_ID(msgOut.m_strAssetID);
	
	OTIdentifier BASKET_ACCOUNT_ID;
	
	// Either way, we need to send the user's command back to him as well.
	{
		OTString tempInMessage(MsgIn);
		msgOut.m_ascInReferenceTo.SetString(tempInMessage);
	}
	
	// Set up some account pointer lists for later...
	listOfAccounts  listUserAccounts, listServerAccounts;
	
	// Here's the request from the user.
	OTString strBasket(MsgIn.m_ascPayload);
	OTBasket theBasket, theRequestBasket;
	
	long lTransferAmount = 0;

	// Now we have the Contract ID from the basket account, 
	// we can get a pointer to its asset contract...
	
	bool bLookup = LookupBasketAccountIDByContractID(BASKET_CONTRACT_ID, BASKET_ACCOUNT_ID);
	
	OTAccount * pBasketAcct = NULL;

	// if the account we received IS INDEED a basket account, AND
	// we can load the request basket from a string, AND verify its signature...
	if (bLookup && theRequestBasket.LoadContractFromString(strBasket) && theRequestBasket.VerifySignature(theNym))
	{		
		// Load the basket account and make sure it exists.
		pBasketAcct = OTAccount::LoadExistingAccount(BASKET_ACCOUNT_ID, SERVER_ID);
		
		if (NULL == pBasketAcct)
		{
			OTLog::Error("ERROR loading the basket account in OTServer::UserCmdExchangeBasket\n");
			msgOut.m_bSuccess = false;
		}
		// Does it verify?
		// I call VerifySignature here since VerifyContractID was already called in LoadExistingAccount().
		else if (!pBasketAcct->VerifySignature(m_nymServer))
		{
			OTLog::Error("ERROR verifying signature on the basket account in OTServer::UserCmdExchangeBasket\n");
			msgOut.m_bSuccess = false;
		}		
		else 
		{
			// Now we get a pointer to its asset contract...
			OTAssetContract * pContract = GetAssetContract(BASKET_CONTRACT_ID);
			
			// Now let's load up the actual basket, from the actual asset contract.
			if (pContract && 
				theBasket.LoadContractFromString(pContract->GetBasketInfo()) && 
				theBasket.VerifySignature(m_nymServer) &&
				theBasket.Count() == theRequestBasket.Count() && 
				theBasket.GetMinimumTransfer() == theRequestBasket.GetMinimumTransfer())
			{
				// Loop through the request AND the actual basket TOGETHER...
				for (int i = 0; i < theBasket.Count(); i++)
				{
					BasketItem * pBasketItem	= theBasket.At(i);
					BasketItem * pRequestItem	= theRequestBasket.At(i); // we already know these are the same length
					
					// if not equal 
					if (!(pBasketItem->SUB_CONTRACT_ID == pRequestItem->SUB_CONTRACT_ID))
					{
						OTLog::Error("Error: expected asset type IDs to match in OTServer::UserCmdExchangeBasket\n");
						msgOut.m_bSuccess = false;
						break;
					}
					else // if equal
					{
						msgOut.m_bSuccess = true;
						
						// Load up the two accounts and perform the exchange...
						OTAccount * pUserAcct	= OTAccount::LoadExistingAccount(pRequestItem->SUB_ACCOUNT_ID, SERVER_ID);
						
						if (NULL == pUserAcct)
						{
							OTLog::Error("ERROR loading a user's asset account in OTServer::UserCmdExchangeBasket\n");
							msgOut.m_bSuccess = false;
							break;
						}

						OTAccount * pServerAcct	= OTAccount::LoadExistingAccount(pBasketItem->SUB_ACCOUNT_ID, SERVER_ID);

						if (NULL == pServerAcct)
						{
							OTLog::Error("ERROR loading a basket sub-account in OTServer::UserCmdExchangeBasket\n");
							msgOut.m_bSuccess = false;
							break;
						}
						
						// I'm preserving these points, to be deleted at the end.
						// They won't be saved until after ALL debits/credits were successful.
						// Once ALL exchanges are done, THEN it loops through and saves / deletes
						// all the accounts.
						listUserAccounts.push_back(pUserAcct);
						listServerAccounts.push_back(pServerAcct);

						
						// Do they verify?
						// I call VerifySignature here since VerifyContractID was already called in LoadExistingAccount().
						if (!(pUserAcct->GetAssetTypeID() == pBasketItem->SUB_CONTRACT_ID))
						{
							OTLog::Error("ERROR verifying asset type on a user's account in OTServer::UserCmdExchangeBasket\n");
							msgOut.m_bSuccess = false;
							break;
						}		
						else if (!pUserAcct->VerifySignature(m_nymServer))
						{
							OTLog::Error("ERROR verifying signature on a user's asset account in OTServer::UserCmdExchangeBasket\n");
							msgOut.m_bSuccess = false;
							break;
						}		
						else if (!pServerAcct->VerifySignature(m_nymServer))
						{
							OTLog::Error("ERROR verifying signature on a basket sub-account in OTServer::UserCmdExchangeBasket\n");
							msgOut.m_bSuccess = false;
							break;
						}		
						else 
						{
							// the amount being transferred between these two accounts is the minimum transfer amount
							// for the sub-account on the basket, multiplied by 
							lTransferAmount = (pBasketItem->lMinimumTransferAmount * theRequestBasket.GetTransferMultiple());

							// user is performing exchange IN
							if (msgOut.m_bBool)
							{
								if (pUserAcct->Debit(lTransferAmount) && pServerAcct->Credit(lTransferAmount))
								{
									msgOut.m_bSuccess = true;
								}
								else 
								{
									msgOut.m_bSuccess = false;
									OTLog::Output(0, "Unable to Debit user account, or Credit server account, in OTServer::UserCmdExchangeBasket\n");
									break;
								}
							}
							else // user is peforming exchange OUT 
							{
								if (pUserAcct->Credit(lTransferAmount) && pServerAcct->Debit(lTransferAmount))
								{
									msgOut.m_bSuccess = true;
								}
								else 
								{
									msgOut.m_bSuccess = false;
									OTLog::Output(0, "Unable to Credit user account, or Debit server account, in OTServer::UserCmdExchangeBasket\n");
									break;
								}								
							}
						}							
					}
				} // for
			}
			else 
			{
				OTLog::Error("Error finding asset contract for basket, or loading the basket from it, or verifying\n"
								"the signature on that basket, or the request basket didn't match actual basket.\n");
			}
		} // pBasket exists and signature verifies

		
		// Load up the two accounts and perform the exchange...
		OTAccount * pUserMainAcct	= NULL;

		// At this point, if we have successfully debited / credited the sub-accounts.
		// then we need to debit and credit the user's main basket account and the server's basket issuer account.
		if ((true == msgOut.m_bSuccess) && pBasketAcct &&
			(pUserMainAcct = OTAccount::LoadExistingAccount(theRequestBasket.GetRequestAccountID(), SERVER_ID)) &&
			 pUserMainAcct->VerifySignature(m_nymServer) && 
			(pUserMainAcct->GetAssetTypeID() == BASKET_CONTRACT_ID)) // Just make sure the two main basket accts have same currency type
		{
			lTransferAmount =  (theRequestBasket.GetMinimumTransfer() * theRequestBasket.GetTransferMultiple());
			
			// Load up the two accounts and perform the exchange...
			// user is performing exchange IN
			if (msgOut.m_bBool)
			{
				if (pUserMainAcct->Credit(lTransferAmount) && pBasketAcct->Debit(lTransferAmount))
				{
					msgOut.m_bSuccess = true;
				}
				else 
				{
					msgOut.m_bSuccess = false;
					OTLog::Output(0, "Unable to Credit user basket account, or Debit basket issuer account, "
							"in OTServer::UserCmdExchangeBasket\n");
				}
			}
			else // user is peforming exchange OUT 
			{
				if (pUserMainAcct->Debit(lTransferAmount) && pBasketAcct->Credit(lTransferAmount))
				{
					msgOut.m_bSuccess = true;
				}
				else 
				{
					msgOut.m_bSuccess = false;
					OTLog::Output(0, "Unable to Debit user basket account, or Credit basket issuer account, "
							"in OTServer::UserCmdExchangeBasket\n");
				}								
			}
		}
		else {
			OTLog::Error("Error loading or verifying user's main basket account in OTServer::UserCmdExchangeBasket\n");
			msgOut.m_bSuccess = false;
		}
		
		// At this point, we have hopefully credited/debited ALL the relevant accounts.
		// So now, let's Save them ALL to disk.. (and clean them up.)
		OTAccount * pAccount = NULL;

		// empty the list of user accounts (and save to disk, if everything was successful.)
		while (!listUserAccounts.empty())
		{
			pAccount = listUserAccounts.front();
			listUserAccounts.pop_front();
			
			if (true == msgOut.m_bSuccess)
			{
				pAccount->ReleaseSignatures();
				pAccount->SignContract(m_nymServer);
				pAccount->SaveContract();
				pAccount->SaveAccount();
			}
			
			delete pAccount; pAccount=NULL;
		}
		
		// empty the list of server accounts (and save to disk, if everything was successful.)
		while (!listServerAccounts.empty())
		{
			pAccount = listServerAccounts.front();
			listServerAccounts.pop_front();
			
			if (true == msgOut.m_bSuccess)
			{
				pAccount->ReleaseSignatures();
				pAccount->SignContract(m_nymServer);
				pAccount->SaveContract();
				pAccount->SaveAccount();
			}
			
			delete pAccount; pAccount=NULL;
		}
		
		
		if (true == msgOut.m_bSuccess)
		{
			pBasketAcct->ReleaseSignatures();
			pBasketAcct->SignContract(m_nymServer);
			pBasketAcct->SaveContract();
			pBasketAcct->SaveAccount();

			pUserMainAcct->ReleaseSignatures();
			pUserMainAcct->SignContract(m_nymServer);
			pUserMainAcct->SaveContract();
			pUserMainAcct->SaveAccount();
		}

		
		// cleanup
		if (pBasketAcct)
		{
			delete pBasketAcct;
			pBasketAcct = NULL;
		}
		
		if (pUserMainAcct)
		{
			delete pUserMainAcct;
			pUserMainAcct = NULL;
		}
	}
	
	// (2) Sign the Message 
	msgOut.SignContract(m_nymServer);		 
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();
}


// An existing user is creating an asset account.
void OTServer::UserCmdCreateAccount(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	// (1) set up member variables 
	msgOut.m_strCommand		= "@createAccount";	// reply to createAccount
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	
	const OTIdentifier USER_ID(theNym), SERVER_ID(m_strServerID);
	
	OTAccount * pNewAccount = NULL;
	
	// If we successfully create the account, then bundle it in the message XML payload
	if (pNewAccount = OTAccount::GenerateNewAccount(USER_ID, SERVER_ID, m_nymServer, MsgIn))
	{
		OTString tempPayload(*pNewAccount);
		msgOut.m_ascPayload.SetString(tempPayload);
		
		msgOut.m_bSuccess = true;
		
		//		OTLog::Error("DEBUG: GenerateNewAccount successfully returned account pointer. Contents:\n%s\n", tempPayload.Get());
		
		pNewAccount->GetIdentifier(msgOut.m_strAcctID);
		
		delete pNewAccount;
		pNewAccount = NULL;
	}
	
	// Either way, we need to send the user's command back to him as well.
	{
		OTString tempInMessage(MsgIn);
		msgOut.m_ascInReferenceTo.SetString(tempInMessage);
	}
	
	// (2) Sign the Message 
	msgOut.SignContract(m_nymServer);		 
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();
}



void OTServer::NotarizeTransfer(OTPseudonym & theNym, OTAccount & theFromAccount, OTTransaction & tranIn, OTTransaction & tranOut)
{
	// The outgoing transaction is an "atTransfer", that is, "a reply to the transfer request"
	tranOut.SetType(OTTransaction::atTransfer);
		
	OTItem * pItem			= NULL;
	OTItem * pResponseItem	= NULL;
	
	// The incoming transaction may be sent to inboxes and outboxes, and it
	// will probably be bundled in our reply to the user as well. Therefore,
	// let's grab it as a string.
	OTString strInReferenceTo;
	
	// Grab the actual server ID from this object, and use it as the server ID here.
	const OTIdentifier SERVER_ID(m_strServerID), USER_ID(theNym), SERVER_USER_ID(m_nymServer);
	
	// For now, there should only be one of these transfer items inside the transaction.
	// So we treat it that way... I either get it successfully or not.
	if (pItem = tranIn.GetItem(OTItem::transfer))
	{
		// The response item, as well as the inbox and outbox items, will contain a copy
		// of the request item. So I save it into a string here so they can all grab a copy of it
		// into their "in reference to" fields.
		pItem->SaveContract(strInReferenceTo);

		// IDFromAccount is the ID on the "from" Account that was passed in.
		// IDItemFromAccount is the "from" account ID on the transaction Item we are currently examining.
		// IDItemToAccount is the "to" account ID on the transaction item we are currently examining.
		OTIdentifier IDFromAccount(theFromAccount);

		// Server response item being added to server response transaction (tranOut)
		// They're getting SOME sort of response item.
		
		pResponseItem = OTItem::CreateItemFromTransaction(tranOut, OTItem::atTransfer);	 
		pResponseItem->m_Status	= OTItem::rejection; // the default.
		pResponseItem->SetReferenceString(strInReferenceTo); // the response item carries a copy of what it's responding to.
		pResponseItem->SetReferenceToNum(pItem->GetTransactionNum()); // This response item is IN RESPONSE to pItem and its Owner Transaction.
		tranOut.AddItem(*pResponseItem); // the Transaction's destructor will cleanup the item. It "owns" it now.		
				
//		OTString strTestInRefTo2;
//		pResponseItem->GetReferenceString(strTestInRefTo2);
//		OTLog::Error("DEBUG: Item in reference to: %s\n", strTestInRefTo2.Get());

		// Set the ID on the To Account based on what the transaction request said. (So we can load it up.)
		OTAccount * pDestinationAcct = OTAccount::LoadExistingAccount(pItem->GetDestinationAcctID(), SERVER_ID);
	
		// Only accept transfers with positive amounts.
		if (0 > pItem->m_lAmount) 
		{
			OTLog::Output(0, "Attempt to transfer negative balance.\n");
		}
	
		// I'm using the operator== because it exists.
		// If the ID on the "from" account that was passed in,
		// does not match the "Acct From" ID on this transaction item
		else if (!(IDFromAccount == pItem->GetPurportedAccountID()))
		{
			OTLog::Output(0, "Error: 'From' account ID on the transaction does not match 'from' account ID on the transaction item.\n");
		} 
		// ok so the IDs match. Does the destination account exist? 
		else if (NULL == pDestinationAcct)
		{
			OTLog::Output(0, "ERROR verifying existence of the 'to' account in OTServer::NotarizeTransfer\n");
		}
		// Are both of the accounts of the same Asset Type?
		else if (!(theFromAccount.GetAssetTypeID() == pDestinationAcct->GetAssetTypeID()))
		{
			OTString strFromAssetID(theFromAccount.GetAssetTypeID()), 
			strDestinationAssetID(pDestinationAcct->GetAssetTypeID());
			OTLog::vOutput(0, "ERROR - user attempted to transfer between accounts of 2 different "
					"asset types in OTServer::NotarizeTransfer:\n%s\n%s\n", strFromAssetID.Get(),
					strDestinationAssetID.Get());
		}
		// Does it verify?
		// I call VerifySignature here since VerifyContractID was already called in LoadExistingAccount().
		else if (!pDestinationAcct->VerifySignature(m_nymServer))
		{
			OTLog::Output(0, "ERROR verifying signature on, the 'to' account in OTServer::NotarizeTransfer\n");
		}
		
		// This entire function can be divided into the top and bottom halves.
		// The top half is oriented around finding the "transfer" item (in the "transfer" transaction)
		// and setting up the response item that will go into the response transaction.
		// The bottom half is oriented, in the case of success, around creating the necessary inbox
		// and outbox entries, and debiting the account, and basically performing the actual transfer.
		else 
		{			
			// Okay then, everything checks out. Let's add this to the sender's outbox and the recipient's inbox. 
			// IF they can be loaded up from file, or generated, that is. 

			// Load the inbox/outbox in case they already exist
			OTLedger	theFromOutbox(USER_ID, IDFromAccount, SERVER_ID), 
						theToInbox(pItem->GetDestinationAcctID(), SERVER_ID);
			
			bool bSuccessLoadingInbox	= theToInbox.LoadInbox();
			bool bSuccessLoadingOutbox	= theFromOutbox.LoadOutbox();
			
			// --------------------------------------------------------------------
			
			// ...or generate them otherwise...

			if (true == bSuccessLoadingInbox)
				bSuccessLoadingInbox	= theToInbox.VerifyAccount(m_nymServer);
			else
				bSuccessLoadingInbox	= theToInbox.GenerateLedger(pItem->GetDestinationAcctID(), SERVER_ID, OTLedger::inbox, true); // bGenerateFile=true
			
			
			// --------------------------------------------------------------------
			
			if (true == bSuccessLoadingOutbox)
				bSuccessLoadingOutbox	= theFromOutbox.VerifyAccount(m_nymServer);
			else
				bSuccessLoadingOutbox	= theFromOutbox.GenerateLedger(IDFromAccount, SERVER_ID, OTLedger::outbox, true); // bGenerateFile=true
			
			
			// --------------------------------------------------------------------
			
			if (false == bSuccessLoadingInbox || false == bSuccessLoadingOutbox)
			{
				OTLog::Error("ERROR generating ledger in OTServer::NotarizeTransfer.\n");
			}
			else 
			{
				// Generate new transaction numbers for these new transactions
				// todo check this generation for failure (can it fail?)
				long lNewTransactionNumber;
				
				IssueNextTransactionNumber(m_nymServer, lNewTransactionNumber, false); // bStoreTheNumber = false
				OTTransaction * pOutboxTransaction	= OTTransaction::GenerateTransaction(theFromOutbox, OTTransaction::pending,
																						 lNewTransactionNumber);
//				IssueNextTransactionNumber(m_nymServer, lNewTransactionNumber, false); // bStoreTheNumber = false
				OTTransaction * pInboxTransaction	= OTTransaction::GenerateTransaction(theToInbox, OTTransaction::pending,
																						 lNewTransactionNumber);
							
				// UPDATE: I am now issuing one new transaction number above, instead of two. This is to make it easy
				// for the two to cross-reference each other. Later if I want to remove the transaction from the inbox
				// and need to know the corresponding transaction # for the outbox, it will be the same number.
				
				// the new transactions store a record of the item they're referring to.
				pOutboxTransaction->SetReferenceString(strInReferenceTo);
				pOutboxTransaction->SetReferenceToNum(pItem->GetTransactionNum());
				
				//todo put these two together in a method.
				pInboxTransaction->	SetReferenceString(strInReferenceTo);
				pInboxTransaction->SetReferenceToNum(pItem->GetTransactionNum());
				
													  
				// Now we have created 2 new transactions from the server to the users' boxes
				// Let's sign them and add to their inbox / outbox.
				pOutboxTransaction->SignContract(m_nymServer);
				pInboxTransaction->	SignContract(m_nymServer);
				pOutboxTransaction->SaveContract();
				pInboxTransaction->	SaveContract();

				// Deduct the amount from the account...
				// TODO an issuer account here, can go negative.
				// whereas a regular account should not be allowed to go negative.
				if (theFromAccount.Debit(pItem->m_lAmount))
				{//todo need to be able to "roll back" if anything inside this block fails.
					// Here the transactions we just created are actually added to the ledgers.
					theFromOutbox.	AddTransaction(*pOutboxTransaction);
					theToInbox.		AddTransaction(*pInboxTransaction);
					
					// Release any signatures that were there before (They won't
					// verify anymore anyway, since the content has changed.)
					theFromAccount.	ReleaseSignatures();
					theFromOutbox.	ReleaseSignatures();
					theToInbox.		ReleaseSignatures();
					
					// Sign all three of them.
					theFromAccount.	SignContract(m_nymServer);
					theFromOutbox.	SignContract(m_nymServer);
					theToInbox.		SignContract(m_nymServer);
					
					// Save all three of them internally
					theFromAccount.	SaveContract();
					theFromOutbox.	SaveContract();
					theToInbox.		SaveContract();
					
					// Save all three of their internals (signatures and all) to file.
					theFromAccount.	SaveAccount();
					theFromOutbox.	SaveOutbox();
					theToInbox.		SaveInbox();
					
					// Now we can set the response item as an acknowledgment instead of the default (rejection)
					// otherwise, if we never entered this block, then it would still be set to rejection, and the
					// new items would never have been added to the inbox/outboxes, and those files, along with
					// the account file, would never have had their signatures released, or been re-signed or 
					// re-saved back to file.  The debit failed, so all of those other actions would fail also.
					// BUT... if the message comes back with ACKNOWLEDGMENT--then all of these actions must have
					// happened, and here is the server's signature to prove it.
					// Otherwise you get no items and no signature. Just a rejection item in the response transaction.
					pResponseItem->m_Status	= OTItem::acknowledgement;
				}
				else {
					delete pOutboxTransaction; pOutboxTransaction = NULL;
					delete pInboxTransaction; pInboxTransaction = NULL;
					OTLog::vOutput(0, "Unable to debit account in OTServer::NotarizeTransfer:  %ld\n", pItem->m_lAmount);
				}
			} // both boxes were successfully loaded or generated.
		}
		
		if (pDestinationAcct)
		{
			delete pDestinationAcct;
			pDestinationAcct = NULL;
		}
		
		// sign the response item before sending it back (it's already been added to the transaction above)
		// Now, whether it was rejection or acknowledgment, it is set properly and it is signed, and it
		// is owned by the transaction, who will take it from here.
		pResponseItem->SignContract(m_nymServer);
		pResponseItem->SaveContract(); // the signing was of no effect because I forgot to save.
		
//		OTString strTestInRefTo;
//		pResponseItem->GetReferenceString(strTestInRefTo);
//		OTLog::vError("DEBUG: Item in reference to: %s\n", strTestInRefTo.Get());
		
	} // if pItem = tranIn.GetItem(OTItem::transfer)
	else {
		OTLog::Error("Error, expected OTItem::transfer in OTServer::NotarizeTransfer\n");
	}
}





// NotarizeWithdrawal supports two withdrawal types:
//
// OTItem::withdrawVoucher	This is a bank voucher, like a cashier's check. Funds are transferred to
//							the bank, who then issues a cheque drawn on an internal voucher account.
//
// OTItem::withdrawal		This is a digital cash withdrawal, in the form of untraceable, blinded
//							tokens. Funds are transferred to the bank, who blind-signs the tokens.
//
void OTServer::NotarizeWithdrawal(OTPseudonym & theNym, OTAccount & theAccount, 
								  OTTransaction & tranIn, OTTransaction & tranOut)
{
	// The outgoing transaction is an "atWithdrawal", that is, "a reply to the withdrawal request"
	tranOut.SetType(OTTransaction::atWithdrawal);
	
	OTItem * pItem			= NULL;
	OTItem * pResponseItem	= NULL;
	
	// The incoming transaction may be sent to inboxes and outboxes, and it
	// will probably be bundled in our reply to the user as well. Therefore,
	// let's grab it as a string.
	OTString strInReferenceTo;
	
	// Grab the actual server ID from this object, and use it as the server ID here.
	const OTIdentifier	SERVER_ID(m_strServerID),		USER_ID(theNym), ACCOUNT_ID(theAccount),
						SERVER_USER_ID(m_nymServer),	ASSET_TYPE_ID(theAccount.GetAssetTypeID());
	
	OTString strAssetTypeID(ASSET_TYPE_ID);
	
	// ------------------------------------------------------------------------
	//
	// WITHDRAW VOUCHER (like a cashier's cheque) is the top half of this function.
	//
	// For digital cash (blinded tokens), see the bottom half of this function.
	//
	
	
	if (pItem = tranIn.GetItem(OTItem::withdrawVoucher))
	{
		// The response item will contain a copy of the request item. So I save it into a string 
		// here so they can all grab a copy of it into their "in reference to" fields.
		pItem->SaveContract(strInReferenceTo);
		
		// Server response item being added to server response transaction (tranOut)
		// (They're getting SOME sort of response item.)
		
		pResponseItem = OTItem::CreateItemFromTransaction(tranOut, OTItem::atWithdrawVoucher);	 
		pResponseItem->m_Status	= OTItem::rejection; // the default.
		pResponseItem->SetReferenceString(strInReferenceTo); // the response item carries a copy of what it's responding to.
		pResponseItem->SetReferenceToNum(pItem->GetTransactionNum()); // This response item is IN RESPONSE to pItem and its Owner Transaction.
		tranOut.AddItem(*pResponseItem); // the Transaction's destructor will cleanup the item. It "owns" it now.		
		
		OTAccount	* pVoucherReserveAcct	= NULL; // contains the server's funds to back vouchers of a specific asset type.
		
		// I'm using the operator== because it exists.
		// If the ID on the "from" account that was passed in,
		// does not match the "Acct From" ID on this transaction item
		if (!(ACCOUNT_ID == pItem->GetPurportedAccountID()))
		{
			OTLog::Output(0, "Error: Account ID does not match account ID on the withdrawal item.\n");
		} 
		
		// The server will already have a special account for issuing vouchers. Actually, a list of them --
		// one for each asset type. Since this is the normal way of doing business, GetVoucherAccount() will
		// just create it if it doesn't already exist, and then return the pointer. Therefore, a failure here
		// is a catastrophic failure!  Should never fail.
		else if ((pVoucherReserveAcct = GetVoucherAccount(ASSET_TYPE_ID)) &&
				 pVoucherReserveAcct->VerifyAccount(m_nymServer))
		{					
			OTString strVoucherRequest, strItemNote;
			pItem->GetNote(strItemNote);
			pItem->GetAttachment(strVoucherRequest);
			
			OTIdentifier VOUCHER_ACCOUNT_ID(*pVoucherReserveAcct);
			
			OTCheque	theVoucher(SERVER_ID, ASSET_TYPE_ID),
						theVoucherRequest(SERVER_ID, ASSET_TYPE_ID);
			
			bool bLoadContractFromString = theVoucherRequest.LoadContractFromString(strVoucherRequest);
			
			if (!bLoadContractFromString)
			{
				OTLog::vError("ERROR loading voucher request from string in OTServer::NotarizeWithdrawal:\n%s\n",
						strVoucherRequest.Get());
			}
			else // successfully loaded the voucher request from the string...
			{
				OTString strChequeMemo;
				strChequeMemo.Format("%s\n%s", strItemNote.Get(), theVoucherRequest.GetMemo().Get());
				
				// 10 minutes ==    600 Seconds
				// 1 hour	==     3600 Seconds
				// 1 day	==    86400 Seconds
				// 30 days	==  2592000 Seconds
				// 3 months ==  7776000 Seconds
				// 6 months == 15552000 Seconds
				
				const time_t	VALID_FROM	= time(NULL);			// This time is set to TODAY NOW
				const time_t	VALID_TO	= VALID_FROM + 15552000;// This time occurs in 180 days (6 months)
				
				long lNewTransactionNumber;
				IssueNextTransactionNumber(m_nymServer, lNewTransactionNumber); // bStoreTheNumber defaults to true. We save the transaction
																				// number on the server Nym (normally we'd discard it) because
				const long lAmount = theVoucherRequest.GetAmount();				// when the cheque is deposited, the server nym, as the owner of
				const OTIdentifier & RECIPIENT_ID = theVoucherRequest.GetRecipientUserID();	// the voucher account, needs to verify the transaction # on the
																				// cheque (to prevent double-spending of cheques.)
				bool bIssueVoucher = theVoucher.IssueCheque(
										lAmount,				// The amount of the cheque.
										lNewTransactionNumber,	// Requiring a transaction number prevents double-spending of cheques.
										VALID_FROM,				// The expiration date (valid from/to dates) of the cheque
										VALID_TO,				// Vouchers are automatically starting today and lasting 6 months.
										VOUCHER_ACCOUNT_ID,		// The asset account the cheque is drawn on.
										SERVER_USER_ID,			// User ID of the sender (in this case the server.)
										strChequeMemo.Get(),	// Optional memo field. Includes item note and request memo.
										theVoucherRequest.HasRecipient() ? (&RECIPIENT_ID) : NULL);

				// IF we successfully created the voucher, AND the voucher amount is greater than 0,
				// AND debited the user's account,
				// AND credited the server's voucher account,
				//
				// THEN save the accounts and return the voucher to the user.
				//
				if (bIssueVoucher					&& (lAmount > 0)				&&
					theAccount.				Debit(theVoucherRequest.GetAmount())	&&
					pVoucherReserveAcct->	Credit(theVoucherRequest.GetAmount()))
				{
					OTString strVoucher;
					theVoucher.SetAsVoucher();	// All this does is set the voucher's internal contract 
												// string to "VOUCHER" instead of "CHEQUE". 
					theVoucher.SignContract(m_nymServer);
					theVoucher.SaveContract();
					theVoucher.SaveContract(strVoucher);
					
					pResponseItem->SetAttachment(strVoucher);
					pResponseItem->m_Status	= OTItem::acknowledgement;
					
					
					// Release any signatures that were there before (They won't
					// verify anymore anyway, since the content has changed.)
					theAccount.	ReleaseSignatures();
					theAccount.	SignContract(m_nymServer);	// Sign 
					theAccount.	SaveContract();				// Save 
					theAccount.	SaveAccount();				// Save to file
					
					// We also need to save the Voucher cash reserve account.
					// (Any issued voucher cheque is automatically backed by this reserve account.
					// If a cheque is deposited, the funds come back out of this account. If the
					// cheque expires, then after the expiry period, if it remains in the account,
					// it is now the property of the transaction server.)
					pVoucherReserveAcct->ReleaseSignatures();
					pVoucherReserveAcct->SignContract(m_nymServer);
					pVoucherReserveAcct->SaveContract();
					pVoucherReserveAcct->SaveAccount();					
				}	
				//else{} // TODO log that there was a problem with the amount
				
			} // voucher request loaded successfully from string
		} // GetVoucherAccount()
		else {
			OTLog::vError("GetVoucherAccount() failed in NotarizeWithdrawal. Asset Type:\n%s\n",
					strAssetTypeID.Get());
		}
		
		// sign the response item before sending it back (it's already been added to the transaction above)
		// Now, whether it was rejection or acknowledgment, it is set properly and it is signed, and it
		// is owned by the transaction, who will take it from here.
		pResponseItem->SignContract(m_nymServer);
		pResponseItem->SaveContract(); // the signing was of no effect because I forgot to save.
		
	}
	
	// --------------------------------------------------------------------------------------
	
	// WITHDRAW DIGITAL CASH (BLINDED TOKENS)
	//
	// For now, there should only be one of these withdrawal items inside the transaction.
	// So we treat it that way... I either get it successfully or not.
	else if (pItem = tranIn.GetItem(OTItem::withdrawal))
	{
		// The response item will contain a copy of the request item. So I save it into a string 
		// here so they can all grab a copy of it into their "in reference to" fields.
		pItem->SaveContract(strInReferenceTo);
		
		// Server response item being added to server response transaction (tranOut)
		// They're getting SOME sort of response item.
		
		pResponseItem = OTItem::CreateItemFromTransaction(tranOut, OTItem::atWithdrawal);	 
		pResponseItem->m_Status	= OTItem::rejection; // the default.
		pResponseItem->SetReferenceString(strInReferenceTo); // the response item carries a copy of what it's responding to.
		pResponseItem->SetReferenceToNum(pItem->GetTransactionNum()); // This response item is IN RESPONSE to pItem and its Owner Transaction.
		tranOut.AddItem(*pResponseItem); // the Transaction's destructor will cleanup the item. It "owns" it now.		
		
		OTMint		* pMint = NULL;
		OTAccount	* pMintCashReserveAcct = NULL;
	
		if (0 > pItem->m_lAmount)
		{
			OTLog::Output(0, "Attempt to withdraw a negative amount.\n");
		}
	
		// I'm using the operator== because it exists.
		// If the ID on the "from" account that was passed in,
		// does not match the "Acct From" ID on this transaction item
		else if (!(ACCOUNT_ID == pItem->GetPurportedAccountID()))
		{
			OTLog::Output(0, "Error: 'From' account ID on the transaction does not match 'from' account ID on the withdrawal item.\n");
		} 
				
		else
		{			
			// The COIN REQUEST (including the prototokens) comes from the client side.
			// so we assume the OTToken is in the payload. Now we need to randomly choose one for
			// signing, and reply to the client with that number so that the client can reply back
			// to us with the unblinding factors for all the other prototokens (but that one.)
			//
			// In the meantime, I have to store this request somewhere -- presumably in the outbox or purse.
			// 
			// UPDATE!!! Looks like Lucre protocol is simpler than that. The request only needs to contain a
			// single blinded token, which the server signs and sends back. Done.
			//
			// The amount is known to be safe (by the mint) because the User asks the Mint to create
			// a denomination (say, 10) token. The Mint therefore uses the "Denomination 10" key to sign
			// the token, and will later use the "Denomination 10" key to verify the token. So the mint
			// obviously trusts its own keys... There is nothing else to "open and verify", since only the ID
			// itself is what gets blinded and verified.  The amount on the token (as well as the asset type)
			// is only there to help the bank to look up the right key, without which the token will DEFINITELY
			// NOT verify. So it is in the user's interest to supply the correct amount, because otherwise he'll
			// just get the wrong key and then get rejected by the bank.
			
			OTString strPurse;
			pItem->GetAttachment(strPurse);
			
			// Todo do more security checking in here, like making sure the withdrawal amount matches the
			// total of the proto-tokens. Update: I think this is done, since the Debits are done one-at-a-time
			// for each token and it's amount/denomination
			
			OTPurse thePurse(SERVER_ID, ASSET_TYPE_ID);
			OTPurse theOutputPurse(SERVER_ID, ASSET_TYPE_ID); 
			OTToken * pToken = NULL;
			dequeOfTokenPtrs theDeque;
			
			bool bSuccess = false;
			bool bLoadContractFromString = thePurse.LoadContractFromString(strPurse);
			
			if (!bLoadContractFromString)
			{
				OTLog::vError("ERROR loading purse from string in OTServer::NotarizeWithdrawal:\n%s\n",
						strPurse.Get());
			}
			else // successfully loaded the purse from the string...
			{
				// Pull the token(s) out of the purse that was received from the client.
				while (pToken = thePurse.Pop(m_nymServer))
				{
					// We are responsible to cleanup pToken
					// So I grab a copy here for later...
					theDeque.push_front(pToken);
					
					if ((pMint = GetMint(ASSET_TYPE_ID, pToken->GetSeries())) &&
						(pMintCashReserveAcct = pMint->GetCashReserveAccount()) &&
						!pMint->Expired())	// Mints expire halfway into their token expiration period. So if a mint creates
					{						// tokens valid from Jan 1 through Jun 1, then the Mint itself expires Mar 1.
						// That's when the next series Mint is phased in to start issuing tokens, even
						// though the server continues redeeming the first series tokens until June.
						OTString		theStringReturnVal;
						
						// TokenIndex is for cash systems that send multiple proto-tokens, so the Mint
						// knows which proto-token has been chosen for signing.
						// But Lucre only uses a single proto-token, so the token index is always 0.
						if (!(pToken->GetAssetID() == ASSET_TYPE_ID) ||
							!(pMint->SignToken(m_nymServer, *pToken, theStringReturnVal, 0))) // nTokenIndex = 0 // ******************************************
						{
							bSuccess = false;
							OTLog::Error("ERROR signing token in OTServer::NotarizeWithdrawal\n");
							break;
						}
						else
						{
							OTASCIIArmor	theArmorReturnVal(theStringReturnVal);
							
							pToken->ReleaseSignatures(); // this releases the normal signatures, not the Lucre signed token from the Mint, above.
							
							pToken->SetSignature(theArmorReturnVal, 0); // nTokenIndex = 0
							
							// Sign and Save the token
							pToken->SignContract(m_nymServer);
							pToken->SaveContract();
							
							// Now the token is in signedToken mode, and the other prototokens have been released.
							
							// Deduct the amount from the account...
							if (theAccount.Debit(pToken->GetDenomination()))
							{//todo need to be able to "roll back" if anything inside this block fails.
								bSuccess = true;
								
								// Credit the server's cash account for this asset type in the same
								// amount that was debited. When the token is deposited again, Debit that same
								// server cash account and deposit in the depositor's acct.
								// Why, you might ask? Because if the token expires, the money will stay in 
								// the bank's cash account instead of being lost (and screwing up the overall
								// issuer balance, with the issued money disappearing forever.) The bank knows
								// that once the series expires, whatever funds are left in that cash account are
								// for the bank to keep. They can be transferred to another account and kept, instead
								// of being lost.
								if (!pMintCashReserveAcct->Credit(pToken->GetDenomination()))
								{
									OTLog::Error("Error crediting mint cash reserve account...\n");
									
									// Reverse the account debit (even though we're not going to save it anyway.)
									theAccount.Credit(pToken->GetDenomination());
									bSuccess = false;
									break;
								}
							}
							else {
								bSuccess = false;
								OTLog::Output(0, "Unable to debit account in OTServer::NotarizeWithdrawal.\n");
								break; // Once there's a failure, we ditch the loop.
							}
						}					
					}
					else {
						bSuccess = false;
						OTLog::Error( "Unknown or expired Mint, or missing cash reserve for mint, in OTServer::NotarizeWithdrawal.\n");
						break; // Once there's a failure, we ditch the loop.
					}				
				} // While success popping token out of the purse...
				
				if (bSuccess)
				{
					while (!theDeque.empty()) 
					{
						pToken = theDeque.front();
						theDeque.pop_front();
						
						theOutputPurse.Push(theNym, *pToken); // these were in reverse order. Fixing with theDeque.
						
						delete pToken;
						pToken = NULL;
					} 
					
					strPurse.Release(); // just in case it only concatenates.
					
					theOutputPurse.SignContract(m_nymServer);
					theOutputPurse.SaveContract(); // todo this is probably unnecessary
					theOutputPurse.SaveContract(strPurse);				
					
					
					// Add the digital cash token to the response message
					pResponseItem->SetAttachment(strPurse);
					pResponseItem->m_Status	= OTItem::acknowledgement;
					
					// Release any signatures that were there before (They won't
					// verify anymore anyway, since the content has changed.)
					theAccount.	ReleaseSignatures();
					
					// Sign 
					theAccount.	SignContract(m_nymServer);
					
					// Save 
					theAccount.	SaveContract();
					
					// Save to file
					theAccount.	SaveAccount();
					
					// We also need to save the Mint's cash reserve.
					// (Any cash issued by the Mint is automatically backed by this reserve
					// account. If cash is deposited, it comes back out of this account. If the
					// cash expires, then after the expiry period, if it remains in the account,
					// it is now the property of the transaction server.)
					pMintCashReserveAcct->ReleaseSignatures();
					pMintCashReserveAcct->SignContract(m_nymServer);
					pMintCashReserveAcct->SaveContract();
					pMintCashReserveAcct->SaveAccount();
					
					// Notice if there is any failure in the above loop, then we will never enter this block.
					// Therefore the account will never be saved with the new debited balance, and the output
					// purse will never be added to the response item.  No tokens will be returned to the user
					// and the account will not be saved, thus retaining the original balance.
					//
					// Only if everything is successful do we enter this block, save the output purse onto the
					// response, and save the newly-debitted account back to disk.
				}
				// Still need to clean up theDeque
				else 
				{
					while (!theDeque.empty()) 
					{
						pToken = theDeque.front();
						theDeque.pop_front();
						
						delete pToken;
						pToken = NULL;
					} 				
				}
				
			} // purse loaded successfully from string
			
		} // the Account ID on the item matched properly
		
		
		
		// sign the response item before sending it back (it's already been added to the transaction above)
		// Now, whether it was rejection or acknowledgment, it is set properly and it is signed, and it
		// is owned by the transaction, who will take it from here.
		pResponseItem->SignContract(m_nymServer);
		pResponseItem->SaveContract(); // the signing was of no effect because I forgot to save.
		
	} // if pItem = tranIn.GetItem(OTItem::withdrawal)
	else {
		OTLog::Error( "Error, expected OTItem::withdrawal in OTServer::NotarizeWithdrawal\n");
	}	
}
												  
												  
// for depositing a cheque or cash.
void OTServer::NotarizeDeposit(OTPseudonym & theNym, OTAccount & theAccount, OTTransaction & tranIn, OTTransaction & tranOut)
{
	// The outgoing transaction is an "atDeposit", that is, "a reply to the deposit request"
	tranOut.SetType(OTTransaction::atDeposit);
	
	OTItem * pItem			= NULL;
	OTItem * pResponseItem	= NULL;
	
	// The incoming transaction may be sent to inboxes and outboxes, and it
	// will probably be bundled in our reply to the user as well. Therefore,
	// let's grab it as a string.
	OTString strInReferenceTo;
	
	// Grab the actual server ID from this object, and use it as the server ID here.
	const OTIdentifier	SERVER_ID(m_strServerID),		USER_ID(theNym),	ACCOUNT_ID(theAccount),
						SERVER_USER_ID(m_nymServer),	ASSET_TYPE_ID(theAccount.GetAssetTypeID());
	
	OTString strUserID(USER_ID), strAccountID(ACCOUNT_ID);
	
	OTMint		* pMint					= NULL; // the Mint itself.
	OTAccount	* pMintCashReserveAcct	= NULL; // the Mint's funds for cash withdrawals.


	// -------------------------------------------------------------------------------------------
	// DEPOSIT CHEQUE  (Deposit Cash is the bottom half of the function, deposit cheque is the top half.)
	
	// Deposit (the transaction) now supports deposit (the item) and depositCheque (the item)
	if (pItem = tranIn.GetItem(OTItem::depositCheque))
	{
		// The response item, as well as the sender's inbox, will soon contain a copy
		// of the request item. So I save it into a string here so they can grab a copy of it
		// into their "in reference to" fields.
		pItem->SaveContract(strInReferenceTo);
		
		// Server response item being added to server response transaction (tranOut)
		// They're getting SOME sort of response item.
		
		pResponseItem = OTItem::CreateItemFromTransaction(tranOut, OTItem::atDepositCheque);	 
		pResponseItem->m_Status	= OTItem::rejection; // the default.
		pResponseItem->SetReferenceString(strInReferenceTo); // the response item carries a copy of what it's responding to.
		pResponseItem->SetReferenceToNum(pItem->GetTransactionNum()); // This response item is IN RESPONSE to pItem and its Owner Transaction.
		tranOut.AddItem(*pResponseItem); // the Transaction's destructor will cleanup the item. It "owns" it now.		
		
		// I'm using the operator== because it exists.
		// If the ID on the "from" account that was passed in,
		// does not match the "Acct From" ID on this transaction item
		if (!(ACCOUNT_ID == pItem->GetPurportedAccountID()))
		{
			OTLog::Output(0, "Error: account ID does not match account ID on the deposit item.\n");
		} 
		else
		{
			OTString strCheque;
			pItem->GetAttachment(strCheque);
			
			OTCheque theCheque(SERVER_ID, ASSET_TYPE_ID); 
			
			bool bLoadContractFromString = theCheque.LoadContractFromString(strCheque);
			
			if (!bLoadContractFromString)
			{
				OTLog::vError("ERROR loading cheque from string in OTServer::NotarizeDeposit:\n%s\n",
						strCheque.Get());
			}
			else
			{
				OTIdentifier & SOURCE_ACCT_ID		= theCheque.GetSenderAcctID();
				OTIdentifier & SENDER_USER_ID		= theCheque.GetSenderUserID();
				OTIdentifier & RECIPIENT_USER_ID	= theCheque.GetRecipientUserID();
				
				OTString	strSenderUserID(SENDER_USER_ID), strRecipientUserID(RECIPIENT_USER_ID),
							strSourceAcctID(SOURCE_ACCT_ID);

				OTAccount *	pSourceAcct = NULL;
				
				OTPseudonym		theSenderNym(SENDER_USER_ID);
				OTPseudonym *	pSenderNym = &theSenderNym;
								
				// Don't want to overwrite files or db records in cases where the sender is also the depositor.
				// (Similar concern if the server is also the depositor, but that's already partly handled
				// before we get to this point... theNym is already substituted for m_nymServer,
				// if the IDs match, before any of the commands are processed.)
				//
				// The conundrum is in the multiplicity of combinations. The server COULD be the sender
				// OR the depositor, or he could be BOTH, or the server might NOT be the sender OR depositor,
				// yet they could still be the same person.  Normally all 3 are separate entities.  That's a
				// lot of combinations. I want to make sure that I don't overwrite ANY files while juggling the 
				// respective nymfiles, transaction numbers, request numbers, etc.
				//
				// Solution:  When commands are first processed, and the Request Number is processed, theNym
				// is ALREADY replaced with m_nymServer IF the IDs match and the signature verifies. It is then
				// passed that way to all of the commands (including the one we are in now.)
				//
				// I THEN do the logic BELOW as additional to that. Make sure if you change anything that you
				// think long and hard about what you are doing!!
				// 
				// Here's the logic:
				// -- theNym is the depositor (for sure.)
				// -- m_nymServer is the server nym (for sure.)
				// -- By the time we get here, IF the ServerUserID and UserID match,
				//	  then theNym IS ALREADY m_nymServer, literally a reference to it.
				//    (This is performed before we even get to this point, so that the 
				//	  same problem doesn't occur with request numbers.)
				// -- In cases where the "server is also the depositor", it's therefore
				//	  ALREADY handled, since theNym already points to m_nymServer.
				// -- theSenderNym is used to load the sender nym in cases where we have 
				//	  to load it from file or db ourselves. (Most normal cases.)
				// -- In those normal cases, pSenderNym will point to theSenderNym and
				//	  we load it up from file or database.
				// -- In cases where the sender is also the user (the depositor), then
				//	  pSenderNym will point to theNym instead of to theSenderNym, and we
				//	  no longer bother loading it, since the user is already loaded.
				// -- In cases where the sender is also the server, then pSenderNym will
				//	  point to m_nymServer instead of to theSenderNym, and we no longer
				//	  bother loading it, since the server's nym is already loaded.
				
				bool	bDepositorIsServer	= ((USER_ID			== SERVER_USER_ID)	? true	: false);
				bool	bSenderIsServer		= ((SENDER_USER_ID	== SERVER_USER_ID)	? true	: false);
				bool	bDepositorIsSender	= ((SENDER_USER_ID	== USER_ID)			? true	: false);
				
				bool	bSenderAlreadyLoaded = false;
				
				// The depositor is already loaded, (for sure.)
				
				// The server is already loaded, (for sure.)
				
				// If the depositor IS the server, then it already points there (for sure.)
				if (bDepositorIsServer)
				{
					//OTPseudonym & theNym = m_nymServer; // Already handled in the code that calls IncrementRequestNum().
					//bSenderAlreadyLoaded = false; // Sender is either determined to be already loaded (directly below) or 
													// it is loaded as part of the cheque verification process below that.
													// At this point I can't set it because I just don't know yet.
				}
				
				// If the depositor IS the sender, pSenderNym points to depositor, and we're already loaded.
				if (bDepositorIsSender)
				{
					pSenderNym = &theNym;
					bSenderAlreadyLoaded = true;
				}
				
				// If the server IS the sender, pSenderNym points to the server, and we're already loaded.
				if (bSenderIsServer) 
				{
					pSenderNym = &m_nymServer;
					bSenderAlreadyLoaded = true;
				}
	
				OTLedger	theSenderInbox(SENDER_USER_ID, SOURCE_ACCT_ID, SERVER_ID); 
				
				// To deposit a cheque, need to verify:  (in no special order)
				// 
				// -- DONE Load the source account and verify it exists.
				// -- DONE Make sure the source acct is verified for the server signature.
				// -- DONE Make sure the Asset Type of the cheque matches the Asset Type of BOTH source and recipient accts.
				// -- DONE See if there is a Recipient User ID. If so, MAKE SURE it matches the user depositing the cheque!
				// -- DONE See if the Sender User even exists.
				// -- DONE See if the Sender User ID matches the hash of the actual public key in the sender's pubkey file.
				// -- DONE Make sure the cheque has the right server ID.
				// -- DONE Make sure the cheque has not yet EXPIRED.
				// -- DONE Make sure the cheque signature is verified with the sender's pubkey.
				// -- DONE Make sure the account ID on the transaction item matches the depositor account ID.
				// -- DONE Verify the funds are in the source acct.
				//
				// -- DONE Plus deal with sender's inbox.
				
				// Load source account's inbox
				bool bSuccessLoadingInbox	= theSenderInbox.LoadInbox();				
				
				// ...If it loads, verify it. Otherwise, generate it...
				if (true == bSuccessLoadingInbox)
					bSuccessLoadingInbox	= theSenderInbox.VerifyAccount(m_nymServer);
				else
					bSuccessLoadingInbox	= theSenderInbox.GenerateLedger(SOURCE_ACCT_ID, SERVER_ID, OTLedger::inbox, true); // bGenerateFile=true
				
				
				// --------------------------------------------------------------------
				
				if (false == bSuccessLoadingInbox)
				{
					OTLog::vError("ERROR verifying or generating inbox ledger in OTServer::NotarizeDeposit for source acct ID:\n%s\n",
							strSourceAcctID.Get());
				}
				
				// See if the cheque is drawn on the same server as the deposit account (the server running this code right now.)
				else if (!(SERVER_ID == theCheque.GetServerID()))
				{
					OTLog::vOutput(0, "Cheque rejected: Incorrect Server ID. Recipient User ID is:\n%s\n",
							strRecipientUserID.Get());					
				}
				
				// See if the cheque is already expired or otherwise not within it's valid date range.
				else if (false == theCheque.VerifyCurrentDate())
				{
					OTLog::vOutput(0, "Cheque rejected: Not within valid date range. Sender User ID:\n%s\nRecipient User ID:\n%s\n",
							strSenderUserID.Get(), strRecipientUserID.Get());					
				}
				
				// See if we can load the sender's public key (to verify cheque signature)
				// if !bSenderAlreadyLoaded since the server already had its public key loaded at boot-time.
				// (also since the depositor and sender might be the same person.)
				else if (!bSenderAlreadyLoaded && (false == theSenderNym.LoadPublicKey()))
				{
					OTLog::vOutput(0, "Error loading public key for cheque signer during deposit:\n%s\nRecipient User ID:\n%s\n", 
							strSenderUserID.Get(), strRecipientUserID.Get());
				}
		
				// See if the Nym ID (User ID) that we have matches the message digest of the public key.
				else if (false == pSenderNym->VerifyPseudonym())
				{
					OTLog::vOutput(0, "Failure verifying cheque: Bad Sender User ID (fails hash check of pubkey)"
							":\n%s\nRecipient User ID:\n%s\n",
							strSenderUserID.Get(), strRecipientUserID.Get());
				}
				
				// See if we can load the sender's nym file (to verify the transaction # on the cheque)
				// if !bSenderAlreadyLoaded since the server already had its nym file loaded at boot-time.
				// (also since the depositor and sender might be the same person.)
				else if (!bSenderAlreadyLoaded && (false == theSenderNym.LoadSignedNymfile(m_nymServer)))
				{
					OTLog::vOutput(0, "Error loading nymfile for cheque signer during deposit:\n%s\nRecipient User ID:\n%s\n", 
							strSenderUserID.Get(), strRecipientUserID.Get());
				}
				
				// Make sure they're not double-spending this cheque.
				else if (false == VerifyTransactionNumber(*pSenderNym, theCheque.GetTransactionNum()))
				{
					OTLog::vOutput(0, "Failure verifying cheque: Bad transaction number.\nRecipient User ID:\n%s\n",
							strRecipientUserID.Get());					
				}
				
				// Let's see if the sender's signature matches the one on the cheque...
				else if (false == theCheque.VerifySignature(*pSenderNym)) 
				{
					OTLog::vOutput(0, "Failure verifying cheque signature for sender ID:\n%s\nRecipient User ID:\n%s\n",
							strSenderUserID.Get(), strRecipientUserID.Get());					
				}
				
				// If there is a recipient user ID on the check, it must match the user depositing the cheque.
				// (But if there is NO recipient user ID, then it's a blank cheque and ANYONE can deposit it.)
				else if (theCheque.HasRecipient() && !(USER_ID == RECIPIENT_USER_ID))
				{
					OTLog::vOutput(0, "Failure matching cheque recipient to depositor. Depositor User ID:\n%s\n"
							"Cheque Recipient User ID:\n%s\n",
							strUserID.Get(), strRecipientUserID.Get());					
				}
				
				// Try to load the source account (that cheque is drawn on) up into memory. 
				// We'll need to debit funds from it...
				else if (!(pSourceAcct = OTAccount::LoadExistingAccount(SOURCE_ACCT_ID, SERVER_ID)))
				{
					OTLog::vOutput(0, "Cheque deposit failure trying to load source acct, ID:\n%s\nRecipient User ID:\n%s\n",
							strSourceAcctID.Get(), strRecipientUserID.Get());					
				}
				
				// Does it verify?
				// I call VerifySignature here since VerifyContractID was already called in LoadExistingAccount().
				// (Otherwise I might normally call VerifyAccount(), which does both...)
				//
				// Someone can't just alter an account file, because then the server's signature
				// won't verify anymore on that file and transactions will fail such as right here:
				else if (!pSourceAcct->VerifySignature(m_nymServer))
				{
					OTLog::vOutput(0, "ERROR verifying signature on source account while depositing cheque. Acct ID:\n%s\n",
							strAccountID.Get());
					
					delete pSourceAcct;
					pSourceAcct = NULL;
				}
								
				// Need to make sure the signer is the owner of the account...
				else if (!pSourceAcct->VerifyOwner(*pSenderNym))
				{
					OTLog::vOutput(0, "ERROR verifying signer's ownership of source account while depositing cheque. Source Acct ID:\n%s\n",
							strAccountID.Get());
					
					delete pSourceAcct;
					pSourceAcct = NULL;
				}
								
				// Are both of the accounts, AND the cheque, all of the same Asset Type?
				else if (!(theCheque.GetAssetID() == pSourceAcct->GetAssetTypeID()) || 
						 !(theCheque.GetAssetID() == theAccount.GetAssetTypeID()))
				{
					OTString	strSourceAssetID(pSourceAcct->GetAssetTypeID()), 
								strRecipientAssetID(theAccount.GetAssetTypeID());
					
					OTLog::vOutput(0, "ERROR - user attempted to deposit cheque between accounts of 2 different "
							"asset types. Source Acct:\n%s\nType:\n%s\nRecipient Acct:\n%s\nType:\n%s\n",
							strSourceAcctID.Get(), strSourceAssetID.Get(),
							strAccountID.Get(), strRecipientAssetID.Get());
					
					delete pSourceAcct;
					pSourceAcct = NULL;
				}
				
				// Debit Source account, Credit Recipient Account, add to Sender's inbox.
				//
				// Also clear the transaction number so this cheque can't be deposited again.
				else
				{								
					// Deduct the amount from the source account, and add it to the recipient account...
					if (pSourceAcct->Debit(theCheque.GetAmount()) && 
						theAccount.Credit(theCheque.GetAmount()) &&
						
						// Clear the transaction number.
						RemoveTransactionNumber(*pSenderNym, theCheque.GetTransactionNum())
						)
					{	// need to be able to "roll back" if anything inside this block fails.
						// update: actually does pretty good roll-back as it is. The debits and credits
						// don't save unless everything is a success.
						
						// Generate new transaction number (for putting the check in the sender's inbox.)
						// todo check this generation for failure (can it fail?)
						long lNewTransactionNumber;
						
						IssueNextTransactionNumber(m_nymServer, lNewTransactionNumber, false); // bStoreTheNumber = false
						OTTransaction * pInboxTransaction	= OTTransaction::GenerateTransaction(theSenderInbox, OTTransaction::pending,
																								 lNewTransactionNumber);
						
						//todo put these two together in a method.
						pInboxTransaction->SetReferenceString(strInReferenceTo);
						pInboxTransaction->SetReferenceToNum(pItem->GetTransactionNum());
						
						
						// Now we have created a new transaction from the server to the sender's inbox
						// Let's sign and save it...
						pInboxTransaction->SignContract(m_nymServer);
						pInboxTransaction->SaveContract();
						
						// Here the transaction we just created is actually added to the source acct's inbox.
						theSenderInbox.AddTransaction(*pInboxTransaction);
						
						// ---------------------------------------------------------------------------------
						// AT THIS POINT, the source account is debited, the recipient account is credited,
						// and the sender's inbox has had the cheque transaction added to it as his receipt.
						// (He must perform a balance agreement in order to get it out of his inbox.)
						//
						// THERE IS NOTHING LEFT TO DO BUT SAVE THE FILES!!
						
						// Release any signatures that were there before (They won't
						// verify anymore anyway, since the content has changed.)
						pSourceAcct->	ReleaseSignatures();
						theAccount.		ReleaseSignatures();
						theSenderInbox.	ReleaseSignatures();
						
						// Sign all three of them.
						pSourceAcct->	SignContract(m_nymServer);
						theAccount.		SignContract(m_nymServer);
						theSenderInbox.	SignContract(m_nymServer);
						
						// Save all three of them internally
						pSourceAcct->	SaveContract();
						theAccount.		SaveContract();
						theSenderInbox.	SaveContract();
						
						// Save all three of their internals (signatures and all) to file.
						pSourceAcct->	SaveAccount();
						theAccount.		SaveAccount();
						theSenderInbox.	SaveInbox();
						
						// Now we can set the response item as an acknowledgment instead of the default (rejection)
						// otherwise, if we never entered this block, then it would still be set to rejection, and the
						// new item would never have been added to the inbox, and the inbox file, along with the
						// account files, would never have had their signatures released, or been re-signed or 
						// re-saved back to file.  The debit failed, so all of those other actions would fail also.
						// BUT... if the message comes back with ACKNOWLEDGMENT--then all of these actions must have
						// happened, and here is the server's signature to prove it.
						// Otherwise you get no items and no signature. Just a rejection item in the response transaction.
						pResponseItem->m_Status	= OTItem::acknowledgement;
					}
					else 
					{
						OTLog::vOutput(0, "OTServer::NotarizeDeposit cheque: Presumably unable to debit %ld from source account ID:\n%s\n", 
								theCheque.GetAmount(), strSourceAcctID.Get());
					}
					
					// Make sure we clean this up.
					delete pSourceAcct;
					pSourceAcct = NULL;
				}
			} // successfully loaded cheque from string
		} // account ID DOES match item's account ID
		
		
		// sign the response item before sending it back (it's already been added to the transaction above)
		// Now, whether it was rejection or acknowledgment, it is set properly and it is signed, and it
		// is owned by the transaction, who will take it from here.
		pResponseItem->SignContract(m_nymServer);
		pResponseItem->SaveContract(); // the signing was of no effect because I forgot to save.
		
		//		OTString strTestInRefTo;
		//		pResponseItem->GetReferenceString(strTestInRefTo);
		//		OTLog::vOutput(0, "DEBUG: Item in reference to: %s\n", strTestInRefTo.Get());
		
	} // deposit cheque
	
	// ---------------------------------------------------------------------------------
	
	// BELOW -- DEPOSIT CASH
	
	// For now, there should only be one of these deposit items inside the transaction.
	// So we treat it that way... I either get it successfully or not.
	else if (pItem = tranIn.GetItem(OTItem::deposit))
	{
		// The response item, as well as the inbox and outbox items, will contain a copy
		// of the request item. So I save it into a string here so they can all grab a copy of it
		// into their "in reference to" fields.
		pItem->SaveContract(strInReferenceTo);
		
		// Server response item being added to server response transaction (tranOut)
		// They're getting SOME sort of response item.
		
		pResponseItem = OTItem::CreateItemFromTransaction(tranOut, OTItem::atDeposit);	 
		pResponseItem->m_Status	= OTItem::rejection; // the default.
		pResponseItem->SetReferenceString(strInReferenceTo); // the response item carries a copy of what it's responding to.
		pResponseItem->SetReferenceToNum(pItem->GetTransactionNum()); // This response item is IN RESPONSE to pItem and its Owner Transaction.
		tranOut.AddItem(*pResponseItem); // the Transaction's destructor will cleanup the item. It "owns" it now.		
		
		// I'm using the operator== because it exists.
		// If the ID on the "from" account that was passed in,
		// does not match the "Acct From" ID on this transaction item
		if (!(ACCOUNT_ID == pItem->GetPurportedAccountID()))
		{
			OTLog::vOutput(0, "Error: 'From' account ID on the transaction does not match 'from' account ID on the deposit item.\n");
		} 
		else
		{
			OTString strPurse;
			pItem->GetAttachment(strPurse);
						
			OTPurse thePurse(SERVER_ID, ASSET_TYPE_ID); 
			OTToken * pToken = NULL;
			
			bool bLoadContractFromString = thePurse.LoadContractFromString(strPurse);
			
			if (!bLoadContractFromString)
			{
				OTLog::vError("ERROR loading purse from string in OTServer::NotarizeDeposit:\n%s\n",
						strPurse.Get());
			}
			
			// TODO: double-check all verification stuff all around on the purse and token, transaction, mint, etc.

			else // the purse loaded successfully from the string
			{
				bool bSuccess = false;
				
				// Pull the token(s) out of the purse that was received from the client.
				while(pToken = thePurse.Pop(m_nymServer))
				{				
					if ((pMint = GetMint(ASSET_TYPE_ID, pToken->GetSeries())) &&
						(pMintCashReserveAcct = pMint->GetCashReserveAccount()))
					{
						//				OTString DEBUG_STR(*pToken);
						//				OTLog::vError("\n**************\nEXTRACTED TOKEN FROM PURSE:\n%s\n", DEBUG_STR.Get());
						
						OTString	strSpendableToken;
						bool bToken = pToken->GetSpendableString(m_nymServer, strSpendableToken);
						//				OTLog::vError("\n**************\nSPENDABLE STRING:\n%s\n", strSpendableToken.Get());
						

						if (!bToken ||  // if failure getting the spendable token data from the token object
							
							!(pToken->GetAssetID() == ASSET_TYPE_ID) || // or if failure verifying asset type
							
							!(pToken->GetServerID() == SERVER_ID) ||	// or if failure verifying server ID
							
							// This call to VerifyToken verifies the token's Series and From/To dates against the
							// mint's, and also verifies that the CURRENT date is inside that valid date range.
							//
							// It also verifies the Lucre coin data itself against the key for that series and
							// denomination. (The signed and unblinded Lucre coin is finally verified in Lucre
							// using the appropriate Mint private key.)
							!(pMint->VerifyToken(m_nymServer, strSpendableToken, pToken->GetDenomination())) ||
							
							// Lookup the token in the SPENT TOKEN DATABASE, and make sure
							// that it hasn't already been spent...
							pToken->IsTokenAlreadySpent(strSpendableToken)) 
						{
							bSuccess = false;
							OTLog::vOutput(0, "ERROR verifying token in OTServer::NotarizeDeposit\n");
							delete pToken; pToken = NULL;
							break;
						}
						else
						{					
							OTLog::vOutput(0, "SUCCESS verifying token!\n");
							// CREDIT the amount to the account...
							if (theAccount.Credit(pToken->GetDenomination()))
							{	// need to be able to "roll back" if anything inside this block fails.
								// so unless bSuccess is true, I don't save the account below.
								bSuccess = true;
								
								OTLog::vOutput(0, "SUCCESS crediting account.\n");
								
								// two defense mechanisms here:  mint cash reserve acct, and spent token database
								
								if (!pMintCashReserveAcct->Debit(pToken->GetDenomination()))
								{
									OTLog::Error("Error debiting the mint cash reserve account. Re-debiting user's asset account...\n");
									theAccount.Debit(pToken->GetDenomination());
									bSuccess = false;								
									delete pToken; pToken = NULL;
									break;
								}
								
								// Spent token database. This is where the call is made to add 
								// the token to the spent token database.
								// IF IT FAILS, we must set success back to false  :-(
								
								if (!pToken->RecordTokenAsSpent(strSpendableToken))
								{
									OTLog::Error("Error recording token as spent! Re-debiting account...\n");
									
									// Not necessary to put these back up since they aren't being saved (since failure)
									// but I just like being thorough...
									theAccount.Debit(pToken->GetDenomination());
									pMintCashReserveAcct->Credit(pToken->GetDenomination());
									bSuccess = false;								
									delete pToken; pToken = NULL;
									break;
								}
							}
							else {
								bSuccess = false;
								OTLog::Error("Unable to credit account in OTServer::NotarizeDeposit.\n");
								delete pToken; pToken = NULL;
								break;
							}
						}					
					}
					else 
					{
						OTLog::Error("Unable to get pointer to Mint or cash reserve account for Mint in OTServer::NotarizeDeposit.\n");
						delete pToken; pToken = NULL;
						break;
					}
					
					delete pToken;
					pToken = NULL;
					
				} // while success popping token from purse

				if (bSuccess)
				{
					// Release any signatures that were there before (They won't
					// verify anymore anyway, since the content has changed.)
					theAccount.	ReleaseSignatures();
					
					// Sign 
					theAccount.	SignContract(m_nymServer);
					
					// Save 
					theAccount.	SaveContract();
					
					// Save to file
					theAccount.	SaveAccount();
					
					// We also need to save the Mint's cash reserve.
					// (Any cash issued by the Mint is automatically backed by this reserve
					// account. If cash is deposited, it comes back out of this account. If the
					// cash expires, then after the expiry period, if it remains in the account,
					// it is now the property of the transaction server.)
					pMintCashReserveAcct->ReleaseSignatures();
					pMintCashReserveAcct->SignContract(m_nymServer);
					pMintCashReserveAcct->SaveContract();
					pMintCashReserveAcct->SaveAccount();
									
					pResponseItem->m_Status	= OTItem::acknowledgement;				
				}
			} // the purse loaded successfully from the string
		} // the account ID matches correctly to the acct ID on the item.
		
		
		// sign the response item before sending it back (it's already been added to the transaction above)
		// Now, whether it was rejection or acknowledgment, it is set properly and it is signed, and it
		// is owned by the transaction, who will take it from here.
		pResponseItem->SignContract(m_nymServer);
		pResponseItem->SaveContract(); // the signing was of no effect because I forgot to save.
		
		//		OTString strTestInRefTo;
		//		pResponseItem->GetReferenceString(strTestInRefTo);
		//		OTLog::vError("DEBUG: Item in reference to: %s\n", strTestInRefTo.Get());
		
	} // if pItem = tranIn.GetItem(OTItem::deposit)
	else {
		OTLog::Error("Error, expected OTItem::deposit in OTServer::NotarizeDeposit\n");
	}	
}




// If the server receives a notarizeTransactions command, it will be accompanied by a payload
// containing a ledger to be notarized.  UserCmdNotarizeTransactions will loop through that ledger,
// and for each transaction within, it calls THIS method.
// TODO think about error reporting here and sending a message back to user.
void OTServer::NotarizeTransaction(OTPseudonym & theNym, OTTransaction & tranIn, OTTransaction & tranOut)
{
	bool bSuccess = false;
	
	const	long			lTransactionNumber = tranIn.GetTransactionNum();
	const	OTIdentifier	SERVER_ID(m_strServerID), SERVER_USER_ID(m_strServerUserID);
			OTIdentifier	USER_ID;
	theNym.GetIdentifier(	USER_ID);

	OTAccount theFromAccount(USER_ID, tranIn.GetPurportedAccountID(), SERVER_ID);
	
	// Make sure the "from" account even exists...
	if (!theFromAccount.LoadContract())
	{
		OTLog::vOutput(0, "Error loading 'from' account in OTServer::NotarizeTransaction\n");
	}
	// Make sure the Account ID loaded from the file matches the one we just set and used as the filename.
	else if (!theFromAccount.VerifyContractID())
	{
		// this should never happen. How did the wrong ID get into the account file, if the right
		// ID is on the filename itself? and vice versa.
		OTLog::Error("Error verifying account ID in OTServer::NotarizeTransaction\n");
	}
	// Make sure the nymID loaded up in the account as its actual owner matches the nym who was
	// passed in to this function requesting a transaction on this account... otherwise any asshole
	// could do transactions on your account, no?
	else if (!theFromAccount.VerifyOwner(theNym))
	{
		OTLog::vOutput(0, "Error verifying account ownership in OTServer::NotarizeTransaction\n");		
	}
	// Make sure I, the server, have signed this file.
	else if (!theFromAccount.VerifySignature(m_nymServer))
	{
		OTLog::Error("Error verifying server signature on account in OTServer::NotarizeTransaction\n");
	}
	// No need to call VerifyAccount() here since the above calls go above and beyond that method.
	
	else if (!VerifyTransactionNumber(theNym, lTransactionNumber))
	{
		OTLog::Output(0, "Error verifying transaction number on user nym in OTServer::NotarizeTransaction\n");
	}
	
	// any other security stuff?
	// Todo do I need to verify the server ID here as well?
	else
	{
		// TRANSFER (account to account)
		// Alice sends a signed request to the server asking it to
		// transfer from her account ABC to the inbox of account DEF.
		// A copy will also remain in her outbox until canceled or accepted.
		if (OTTransaction::transfer == tranIn.GetType())	
		{													
			OTLog::Output(0, "NotarizeTransaction type: Transfer\n");
			NotarizeTransfer(theNym, theFromAccount, tranIn, tranOut);
			bSuccess = true;
		}
		
		// PROCESS INBOX (currently, all incoming transfers must be accepted.)
		// Bob sends a signed request to the server asking it to reject
		// some of his inbox items and/or accept some into his account DEF.
		else if (OTTransaction::processInbox == tranIn.GetType())	
		{															
			OTLog::Output(0, "NotarizeTransaction type: Process Inbox\n");
			NotarizeProcessInbox(theNym, theFromAccount, tranIn, tranOut);	
			bSuccess = true;
		}
		
		// WITHDRAWAL (cash or voucher)	
		// Alice sends a signed request to the server asking it to debit her
		// account ABC and then issue her a purse full of blinded cash tokens
		// --OR-- a voucher (a cashier's cheque, made out to any recipient's 
		// User ID, or made out to a blank recipient, just like a blank cheque.)
		else if (OTTransaction::withdrawal == tranIn.GetType())	
		{																											
			OTLog::Output(0, "NotarizeTransaction type: Withdrawal\n");
			NotarizeWithdrawal(theNym, theFromAccount, tranIn, tranOut);
			bSuccess = true;
		}
		
		// DEPOSIT	(cash or cheque)
		// Bob sends a signed request to the server asking it to deposit into his
		// account ABC. He includes with his request a signed cheque made out to
		// Bob's user ID (or blank), --OR-- a purse full of tokens.
		else if (OTTransaction::deposit == tranIn.GetType())
		{													
			OTLog::Output(0, "NotarizeTransaction type: Deposit\n");
			NotarizeDeposit(theNym, theFromAccount, tranIn, tranOut);
			bSuccess = true;
		}
		else
		{
			OTLog::Error("NotarizeTransaction type: UNKNOWN -- ERROR\n");	
		}
		
		// Whether success or failure, the user has now burned this transaction number,
		// so we remove it from the nym's file so he can't use it twice.
		if (false == RemoveTransactionNumber(theNym, lTransactionNumber))
		{
			OTLog::Error("Error removing transaction number from user nym in OTServer::NotarizeTransaction\n");
		}
		
		// Add a new transaction number item to each outgoing transaction.
		// So that the client can use it with his next request. Might as well
		// send it now, otherwise the client will have to request one later
		// before his next request.
		long lTransactionNum = 0;
		
		// This call to IssueNextTransactionNumber will save the new transaction
		// number to the nym's file on the server side. 
		if (bSuccess && IssueNextTransactionNumber(theNym, lTransactionNum))
		{
			// But we still have to bundle it into the message and send it, so
			// it can also be saved into the same nym's file on the client side.
			OTPseudonym theMessageNym;
			theMessageNym.AddTransactionNum(m_strServerID, lTransactionNum); // This version of AddTransactionNum doesn't bother saving to file. No need here...
			
			OTString	strMessageNym(theMessageNym);
			
			OTItem * pItem	= OTItem::CreateItemFromTransaction(tranOut, OTItem::atTransaction);
			
			if (pItem)
			{
				pItem->m_Status	= OTItem::acknowledgement;
				pItem->SetAttachment(strMessageNym);
				pItem->SignContract(m_nymServer);
				pItem->SaveContract(); // the signing was of no effect because I forgot to save.
				tranOut.AddItem(*pItem); // the Transaction's destructor will cleanup the item. It "owns" it now.		
			}
		}
	}

	// sign the outoing transaction
	tranOut.SignContract(m_nymServer);	
	tranOut.SaveContract();	 // don't forget to save (to internal raw file member)
	
	// Contracts store an internal member that contains the "Raw File" contents
	// That is, the unsigned XML portion, plus the signatures, attached in a standard
	// PGP-compatible format. It's not enough to sign it, you must also save it into
	// that Raw file member variable (using SaveContract) and then you must sometimes
	// THEN save it into a file (or a string or wherever you want to put it.)
}


// TODO:  the below function needs to call the various transaction functions.
// There will be more code here to handle all that. In the meantime, I just send
// a test response back to make sure the communication works.
//
// An existing user is sending a list of transactions to be notarized.
void OTServer::UserCmdNotarizeTransactions(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	// (1) set up member variables 
	msgOut.m_strCommand		= "@notarizeTransactions";	// reply to notarizeTransactions
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	msgOut.m_strAcctID		= MsgIn.m_strAcctID;	// The Account ID in question
	
	const OTIdentifier	USER_ID(MsgIn.m_strNymID), ACCOUNT_ID(MsgIn.m_strAcctID), SERVER_ID(m_strServerID),
						SERVER_USER_ID(m_nymServer);
	
	OTLedger theLedger(USER_ID, ACCOUNT_ID, SERVER_ID);			// These are ledgers used as messages. The one we received and the one 
																// that we're sending back in response.
	OTLedger * pResponseLedger = OTLedger::GenerateLedger(SERVER_USER_ID, ACCOUNT_ID, SERVER_ID, OTLedger::message, false);
	
	// Since the one going back (above) is a new ledger, we have to call GenerateLedger.
	// Whereas the ledger we received from the server was generated there, so we don't
	// have to generate it again. We just load it.
	
	OTString strLedger(MsgIn.m_ascPayload);
	
	// as long as the request ledger loads from the message into memory, success is true
	// from there, the success or failure of the transactions within will be carried in
	// their own status variables and those of the items inside those transactions.
	if (msgOut.m_bSuccess = theLedger.LoadContractFromString(strLedger))
	{
		// In this case we need to process the ledger items
		// and create a corresponding ledger where each of the new items
		// contains the answer to the ledger item sent.
		// Then we send that new "response ledger" back to the user in MsgOut.Payload.
		// That is all done here. Until I write that, in the meantime,
		// let's just fprintf it out and see what it looks like.
		//		OTLog::Error("Loaded ledger out of message payload:\n%s\n", strLedger.Get());
//		OTLog::Error("Loaded ledger out of message payload.\n");
 		
		// TODO: Loop through ledger transactions, and do a "NotarizeTransaction" call for each one.
		// Inside that function it will do the various necessary authentication and processing, not this one.
		
		OTTransaction * pTransaction	= NULL;
		OTTransaction * pTranResponse	= NULL;
		
		for (mapOfTransactions::iterator ii = theLedger.GetTransactionMap().begin(); 
			 ii != theLedger.GetTransactionMap().end(); ++ii)
		{	
			// for each transaction in the ledger, we create a transaction response and add
			// that to the response ledger.
			if (pTransaction = (*ii).second)
			{
				
				// I don't call IssueNextTransactionNumber here because I'm not creating a new transaction
				// in someone's inbox or outbox. Instead, I'm making a transaction response to a transaction
				// request, with a MATCHING transaction number (so don't need to issue a new one) to be sent
				// back to the client in a message.
				//
				// On this new "response transaction", I set the ACCT ID, the serverID, and Transaction Number.
				pTranResponse = OTTransaction::GenerateTransaction(*pResponseLedger, OTTransaction::error_state, pTransaction->GetTransactionNum());
				// Add the response transaction to the response ledger.
				// That will go into the response message and be sent back to the client.
				pResponseLedger->AddTransaction(*pTranResponse);
				
				// Now let's make sure the response transaction has a copy of the transaction
				// it is responding to.
				//				OTString strResponseTo;
				//				pTransaction->SaveContract(strResponseTo);
				//				pTranResponse->m_ascInReferenceTo.SetString(strResponseTo);
				// I commented out the above because we are keeping too many copies.
				// Message contains a copy of the message it's responding to.
				// Then each transaction contains a copy of the transaction responding to...
				// Then each ITEM in each transaction contains a copy of each item it's responding to.
				//
				// Therefore, for the "notarizeTransactions" message, I have decided (for now) to have
				// the extra copy in the items themselves, and in the overall message, but not in the
				// transactions. Thus, the above is commented out.
				
				
				// It should always return something. Success, or failure, that goes into pTranResponse.
				// I don't think there's need for more return value than that. The user has gotten deep 
				// enough that they deserve SOME sort of response.
				//
				// This function also SIGNS the transaction, so there is no need to sign it after this.
				// There's also no point to change it after this, unless you plan to sign it twice.
				NotarizeTransaction(theNym, *pTransaction, *pTranResponse);
				
				pTranResponse = NULL; // at this point, the ledger now "owns" the response, and will handle deleting it.
			}
			else {
				OTLog::Error("NULL transaction pointer in OTServer::UserCmdNotarizeTransactions\n");
			}		
		}
		
		// TODO: should consider saving a copy of the response ledger here on the server. 
		// Until the user signs off of the responses, maybe the user didn't receive them.
		// The server should be able to re-send them until confirmation, then delete them.
		// So might want to consider a SAVE TO FILE here of that ledger we're sending out...
		
		// sign the ledger
		pResponseLedger->SignContract(m_nymServer);
		pResponseLedger->SaveContract();
		
		// extract the ledger in ascii-armored form
		OTString strPayload(*pResponseLedger);
		
		msgOut.m_ascPayload.SetString(strPayload);  // now the outgoing message has the response ledger in its payload.
	}
	else {
		OTLog::Error("ERROR loading ledger from message in OTServer::UserCmdNotarizeTransactions\n");
	}
	
	
	// todo: consider commenting this out since the transaction reply items already include a copy
	// of the original client communication that the server is responding to. No point beating a
	// dead horse.
	//
	// Send the user's command back to him as well.
	{
		OTString tempInMessage(MsgIn);
		msgOut.m_ascInReferenceTo.SetString(tempInMessage);
	}
	
	// (2) Sign the Message 
	msgOut.SignContract(m_nymServer);		
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();
	
	// cleanup
	if (pResponseLedger)
	{
		delete pResponseLedger;
		pResponseLedger = NULL;
	}
}



void OTServer::UserCmdGetAccount(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	// (1) set up member variables 
	msgOut.m_strCommand		= "@getAccount";	// reply to getAccount
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	msgOut.m_strAcctID		= MsgIn.m_strAcctID;	// The Account ID in question
	
	const OTIdentifier USER_ID(MsgIn.m_strNymID), ACCOUNT_ID(MsgIn.m_strAcctID), SERVER_ID(MsgIn.m_strServerID);
	
	OTAccount * pAccount		= OTAccount::LoadExistingAccount(ACCOUNT_ID, SERVER_ID);
	bool bSuccessLoadingAccount = ((pAccount != NULL) ? true:false );
	
	// Yup the account exists. Yup it has the same user ID.
	if (bSuccessLoadingAccount && (pAccount->GetUserID() == USER_ID))
	{
		msgOut.m_bSuccess = true;
		// extract the account in ascii-armored form on the outgoing message
		OTString strPayload(*pAccount); // first grab it in plaintext string form
		msgOut.m_ascPayload.SetString(strPayload);  // now the outgoing message has the inbox ledger in its payload in base64 form.
	}
	// Send the user's command back to him if failure.
	else
	{
		msgOut.m_bSuccess = false;
		OTString tempInMessage(MsgIn); // Grab the incoming message in plaintext form
		msgOut.m_ascInReferenceTo.SetString(tempInMessage); // Set it into the base64-encoded object on the outgoing message
	}
	
	// (2) Sign the Message 
	msgOut.SignContract((const OTPseudonym &)m_nymServer);
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();
}



void OTServer::UserCmdGetContract(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	// (1) set up member variables 
	msgOut.m_strCommand		= "@getContract";	// reply to getContract
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	msgOut.m_strAssetID		= MsgIn.m_strAssetID;	// The Asset Type ID in question
	
	const OTIdentifier ASSET_TYPE_ID(MsgIn.m_strAssetID);
	
	OTAssetContract * pContract	= GetAssetContract(ASSET_TYPE_ID);
	
	bool bSuccessLoadingContract = ((pContract != NULL) ? true:false );
	
	// Yup the asset contract exists.
	if (bSuccessLoadingContract)
	{
		msgOut.m_bSuccess = true;
		// extract the account in ascii-armored form on the outgoing message
		OTString strPayload(*pContract); // first grab it in plaintext string form
		msgOut.m_ascPayload.SetString(strPayload);  // now the outgoing message has the inbox ledger in its payload in base64 form.
	}
	// Send the user's command back to him if failure.
	else
	{
		msgOut.m_bSuccess = false;
		OTString tempInMessage(MsgIn); // Grab the incoming message in plaintext form
		msgOut.m_ascInReferenceTo.SetString(tempInMessage); // Set it into the base64-encoded object on the outgoing message
	}
	
	// (2) Sign the Message 
	msgOut.SignContract((const OTPseudonym &)m_nymServer);
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();
}



void OTServer::UserCmdGetMint(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	// (1) set up member variables 
	msgOut.m_strCommand		= "@getMint";	// reply to getMint
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	msgOut.m_strAssetID		= MsgIn.m_strAssetID;	// The Asset Type ID in question
	
	const OTIdentifier ASSET_TYPE_ID(MsgIn.m_strAssetID);	
	OTString strMintPath, ASSET_ID_STR(ASSET_TYPE_ID);
	strMintPath.Format("mints/%s.PUBLIC", ASSET_ID_STR.Get()); // todo stop hardcoding paths
	
	OTMint theMint(ASSET_ID_STR.Get(), strMintPath, ASSET_ID_STR.Get());
	
	// You cannot hash the Mint to get its ID. (The ID is a hash of the asset contract.)
	// Instead, you must READ the ID from the Mint file, and then compare it to the one expected
	// to see if they match (similar to how Account IDs are verified.)
	
	//	bool bSuccessLoadingMint = theMint.LoadContract();
	bool bSuccessLoadingMint = theMint.LoadContract();
	
	if (bSuccessLoadingMint)
		bSuccessLoadingMint = theMint.VerifyMint(m_nymServer);
	
	// Yup the asset contract exists.
	if (bSuccessLoadingMint)
	{
		msgOut.m_bSuccess = true;
		
		// extract the account in ascii-armored form on the outgoing message
		OTString strPayload(theMint); // first grab it in plaintext string form
		msgOut.m_ascPayload.SetString(strPayload);  // now the outgoing message has the inbox ledger in its payload in base64 form.
	}
	// Send the user's command back to him if failure.
	else
	{
		msgOut.m_bSuccess = false;
		OTString tempInMessage(MsgIn); // Grab the incoming message in plaintext form
		msgOut.m_ascInReferenceTo.SetString(tempInMessage); // Set it into the base64-encoded object on the outgoing message
	}
	
	// (2) Sign the Message 
	msgOut.SignContract((const OTPseudonym &)m_nymServer);
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();
}




void OTServer::UserCmdGetInbox(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	// (1) set up member variables 
	msgOut.m_strCommand		= "@getInbox";	// reply to getInbox
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	msgOut.m_strAcctID		= MsgIn.m_strAcctID;	// The Account ID in question
	
	const OTIdentifier USER_ID(MsgIn.m_strNymID), ACCOUNT_ID(MsgIn.m_strAcctID), SERVER_ID(MsgIn.m_strServerID);
	
	OTLedger theLedger(USER_ID, ACCOUNT_ID, SERVER_ID);
	
	if (msgOut.m_bSuccess = theLedger.LoadInbox())
	{ 		
		// extract the ledger in ascii-armored form on the outgoing message
		OTString strPayload(theLedger); // first grab it in plaintext string form
		msgOut.m_ascPayload.SetString(strPayload);  // now the outgoing message has the inbox ledger in its payload in base64 form.
	}
	// Send the user's command back to him if failure.
	else
	{
		OTString tempInMessage(MsgIn); // Grab the incoming message in plaintext form
		msgOut.m_ascInReferenceTo.SetString(tempInMessage); // Set it into the base64-encoded object on the outgoing message
	}
	
	// (2) Sign the Message 
	msgOut.SignContract((const OTPseudonym &)m_nymServer);
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();
}



void OTServer::UserCmdProcessInbox(OTPseudonym & theNym, OTMessage & MsgIn, OTMessage & msgOut)
{
	// (1) set up member variables 
	msgOut.m_strCommand		= "@processInbox";	// reply to processInbox
	msgOut.m_strNymID		= MsgIn.m_strNymID;	// UserID
	msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
	msgOut.m_strAcctID		= MsgIn.m_strAcctID;	// The Account ID in question
	
	const OTIdentifier USER_ID(msgOut.m_strNymID), ACCOUNT_ID(MsgIn.m_strAcctID), SERVER_ID(m_strServerID),
	SERVER_USER_ID(m_nymServer);
	
	OTLedger theLedger(USER_ID, ACCOUNT_ID, SERVER_ID);			// These are ledgers used as messages. The one we received 
																// and the one we're sending back.
	OTLedger * pResponseLedger = OTLedger::GenerateLedger(SERVER_USER_ID, ACCOUNT_ID, SERVER_ID, OTLedger::message, false); // bCreateFile=false
	
	// Grab the string (containing the request ledger) out of ascii-armored form.
	OTString strLedger(MsgIn.m_ascPayload);	

	// theLedger contains a single transaction from the client, with an item inside
	// for each inbox transaction the client wants to accept or reject.
	// Let's see if we can load it from the string that came in the message...
	if (msgOut.m_bSuccess = theLedger.LoadContractFromString(strLedger))
	{		
		OTAccount theAccount(USER_ID, ACCOUNT_ID, SERVER_ID);

		if (theAccount.LoadContract())
		{
			// In this case we need to process the transaction items from the ledger
			// and create a corresponding transaction where each of the new items
			// contains the answer to the transaction item sent.
			// Then we send that new "response ledger" back to the user in MsgOut.Payload
			// as an @processInbox message.
			
			OTTransaction * pTransaction	= NULL;
			OTTransaction * pTranResponse	= NULL;
			
			for (mapOfTransactions::iterator ii = theLedger.GetTransactionMap().begin(); 
				 ii != theLedger.GetTransactionMap().end(); ++ii)
			{	
				pTransaction = (*ii).second;
				
				OT_ASSERT_MSG(NULL != pTransaction, "NULL transaction pointer in OTServer::UserCmdProcessInbox\n");
				
				// for each transaction in the ledger, we create a transaction response and add
				// that to the response ledger.
				pTranResponse = OTTransaction::GenerateTransaction(*pResponseLedger, OTTransaction::error_state, pTransaction->GetTransactionNum());
				
				// Add the response transaction to the response ledger.
				// That will go into the response message and be sent back to the client.
				pResponseLedger->AddTransaction(*pTranResponse);
				
				// Now let's make sure the response transaction has a copy of the transaction
				// it is responding to.
				//				OTString strResponseTo;
				//				pTransaction->SaveContract(strResponseTo);
				//				pTranResponse->m_ascInReferenceTo.SetString(strResponseTo);
				// I commented out the above because we are keeping too many copies.
				// Message contains a copy of the message it's responding to.
				// Then each transaction contains a copy of the transaction responding to...
				// Then each ITEM in each transaction contains a copy of each item it's responding to.
				//
				// Therefore, for the "processInbox" message, I have decided (for now) to have
				// the extra copy in the items themselves, and in the overall message, but not in the
				// transactions. Thus, the above is commented out.
				
				
				// It should always return something. Success, or failure, that goes into pTranResponse.
				// I don't think there's need for more return value than that. The user has gotten deep 
				// enough that they deserve SOME sort of response.
				//
				// This function also SIGNS the transaction, so there is no need to sign it after this.
				// There's also no point to change it after this, unless you plan to sign it twice.
				NotarizeProcessInbox(theNym, theAccount, *pTransaction, *pTranResponse);
				
				pTranResponse = NULL; // at this point, the ledger now "owns" the response, and will handle deleting it.
			}
			
			// TODO: should consider saving a copy of the response ledger here on the server. 
			// Until the user signs off of the responses, maybe the user didn't receive them.
			// The server should be able to re-send them until confirmation, then delete them.
			// So might want to consider a SAVE TO FILE here of that ledger we're sending out...
			
			// sign the ledger
			pResponseLedger->SignContract(m_nymServer);
			pResponseLedger->SaveContract();
			// extract the ledger in ascii-armored form
			OTString strPayload(*pResponseLedger);
			// now the outgoing message has the response ledger in its payload.
			msgOut.m_ascPayload.SetString(strPayload); 
		}
	}
	else {
		OTLog::Error("ERROR loading ledger from message in OTServer::UserCmdProcessInbox\n");
	}
	
	
	// todo: consider commenting this out since the transaction reply items already include a copy
	// of the original client communication that the server is responding to. No point beating a
	// dead horse.
	//
	// Send the user's command back to him as well.
	{
		OTString tempInMessage(MsgIn);
		msgOut.m_ascInReferenceTo.SetString(tempInMessage);
	}
	
	// (2) Sign the Message 
	msgOut.SignContract(m_nymServer);		
	
	// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
	//
	// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
	// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
	msgOut.SaveContract();

	if (pResponseLedger)
	{
		delete pResponseLedger;
		pResponseLedger = NULL;
	}
}




// The client may send multiple transactions in the ledger when he calls processInbox.
// This function will be called for each of those.  Each may contain multiple items accepting
// or rejecting certain transactions. The server acknowledges and notarizes those transactions
// accordingly.
// (And each of those transactions must be accepted or rejected in whole.)
void OTServer::NotarizeProcessInbox(OTPseudonym & theNym, OTAccount & theAccount, OTTransaction & tranIn, OTTransaction & tranOut)
{
	// The outgoing transaction is an "atProcessInbox", that is, "a reply to the process inbox request"
	tranOut.SetType(OTTransaction::atProcessInbox);
	
	OTItem * pItem			= NULL;
	OTItem * pResponseItem	= NULL;
	
	// The incoming transaction may be sent to inboxes and outboxes, and it
	// will probably be bundled in our reply to the user as well. Therefore,
	// let's grab it as a string.
	OTString strInReferenceTo;
	
	// Grab the actual server ID from this object, and use it as the server ID here.
	const OTIdentifier SERVER_ID(m_strServerID), ACCOUNT_ID(theAccount), USER_ID(theNym), SERVER_USER_ID(m_nymServer);
	
	// loop through the items that make up the incoming transaction 
	for (listOfItems::iterator ii = tranIn.GetItemList().begin(); ii != tranIn.GetItemList().end(); ++ii)
	{
		if (pItem = *ii) // if pointer not null
		{
			
			// If the client sent an accept item, then let's process it.
			if (OTItem::accept == pItem->m_Type) // ACCEPT
			{
				// The response item will contain a copy of the "accept" request.
				pItem->SaveContract(strInReferenceTo);
				
				
				// Server response item being added to server response transaction (tranOut)
				// They're getting SOME sort of response item.
				
				
				pResponseItem = OTItem::CreateItemFromTransaction(tranOut, OTItem::atAccept);	 
				pResponseItem->m_Status	= OTItem::rejection; // the default.
				pResponseItem->SetReferenceString(strInReferenceTo); // the response item carries a copy of what it's responding to.
				pResponseItem->SetReferenceToNum(pItem->GetTransactionNum());
				
				tranOut.AddItem(*pResponseItem); // the Transaction's destructor will cleanup the item. It "owns" it now.		
				
				
				// Need to load the Inbox first, in order to look up the transaction that
				// the client is accepting. This is possible because the client has included
				// the transaction number.  I'll just look it up in his inbox and then 
				// process it.
				// theAcctID is the ID on the client Account that was passed in.
				OTLedger theInbox(USER_ID, ACCOUNT_ID, SERVER_ID); 
				
				OTTransaction * pServerTransaction = NULL;
				
				if (false == theInbox.LoadInbox())
				{
					OTLog::Error("Error loading inbox during processInbox\n");
				}
				else if (false == theInbox.VerifyAccount(m_nymServer))
				{
					OTLog::Error("Error verifying inbox during processInbox\n");
				}
				// Careful here.  I'm looking up the original transaction number (1, say) which is stored
				// in my inbox as a "in reference to" on transaction number 41. (Which is a pending transaction
				// that the server created in my inbox, and only REFERS to the original transaction, but is not
				// the original transaction in and of itself.)
				else if (pServerTransaction = theInbox.GetPendingTransaction(pItem->GetReferenceToNum()))
				{
					// the accept item will come with the transaction number that
					// it's referring to. So we'll just look up that transaction
					// in the inbox, and now that it's been accepted, we'll process it.
					
					// At this point, pItem points to the client's attempt to accept pOriginalTransaction
					// and pOriginalTransaction is the server's created transaction in my inbox that contains
					// the original item (from the sender) as the "referenced to" object. So let's extract
					// it.
					OTString strOriginalItem;
					pServerTransaction->GetReferenceString(strOriginalItem);

					OTItem * pOriginalItem = OTItem::CreateItemFromString(strOriginalItem, SERVER_ID, pServerTransaction->GetReferenceToNum());

					if (pOriginalItem)
					{
						
						// What are we doing in this code?
						//
						// I need to accept various items that are sitting in my inbox, such as:
						//
						// -- transfers waiting to be accepted (or rejected.)
						//
						// -- cheque deposit receipts waiting to be accepted (they cannot be rejected.)
						//
						// -- an accept (or reject) of my own transfer may be sitting in my inbox.
						//	  in this last case, I'd have to "accept the accept" to get it out of my inbox.
						//    I could also "accept the reject". But I cannot reject either of those; only
						//	  transfers give me the option to reject.
						//
						// ONLY in the case of transfers also do I need to mess around with my account,
						// and the sender's inbox and outbox. In the other cases, I merely need to remove
						// the item from my inbox.
						// Although when 'accepting the reject', I do need to take the money back into
						// my inbox...
						
						
						
						// ----------------------------------------------------------------------------------------------
						
						
						
						// The below block only executes for ACCEPTING a CHEQUE deposit receipt, or
						// for 'Accepting an ACCEPT.'
						//
						// I can't 'Accept a REJECT' without also transferring the rejected money back into
						// my own account. And that means fiddling with my account, and that means it will
						// be in a different block of code than this one.
						//
						// Whereas with accepting a cheque deposit receipt, or accepting an accepted transfer notice,
						// in both of those cases, my account balance doesn't change at all. I just need to accept
						// those notices in order to get them out of my inbox. So that's the simplest case, and it's
						// handled by THIS block of code:
						//
						if (OTItem::accept			== pOriginalItem->GetType() ||	// In these cases, the original item is just an actionless notice
							OTItem::depositCheque	== pOriginalItem->GetType())	// sitting in my inbox that I need to acknowledge in order to remove it.
						{
							// pItem contains the current user's attempt to accept the ['depositCheque' OR 'accept'] located in theOriginalItem.
							// Now we have the user's item and the item he is trying to accept.

							theInbox.	RemoveTransaction(pServerTransaction->GetTransactionNum());
							
							theInbox.	ReleaseSignatures();
							theInbox.	SignContract(m_nymServer);
							theInbox.	SaveContract();
							theInbox.	SaveInbox();
							
							// Now we can set the response item as an acknowledgment instead of the default (rejection)
							pResponseItem->m_Status	= OTItem::acknowledgement;
						}// its type is OTItem::accept or OTItem::depositCheque
						
						
						
						// ----------------------------------------------------------------------------------------------
						
						// TODO: 'Accept a REJECT' -- NEED TO PERFORM THE TRANSFER OF FUNDS BACK TO THE SENDER'S ACCOUNT WHEN TRANSFER IS REJECTED.
						
						else if (OTItem::reject	== pOriginalItem->GetType())
						{
							OTLog::Error("Error: OTItem::reject is NOT YET SUPPORTED by notarizeProcessInbox,\n"
									"so you may not accept these items until the code is updated.\n");

							// pItem contains the current user's attempt to accept the 'reject' located in theOriginalItem.
							// Now we have the user's item and the reject item he is trying to accept (which puts the money BACK IN HIS ACCOUNT.)
							
							//theInbox.	RemoveTransaction(pServerTransaction->GetTransactionNum());
							
							//theInbox.	ReleaseSignatures();
							//theInbox.	SignContract(m_nymServer);
							//theInbox.	SaveContract();
							//theInbox.	SaveInbox();
							
							// Now we can set the response item as an acknowledgment instead of the default (rejection)
							//pResponseItem->m_Status	= OTItem::acknowledgement;
						}// its type is OTItem::accept or OTItem::depositCheque
						
						// ----------------------------------------------------------------------------------------------
						
						
						
						// The below block only executes for ACCEPTING a TRANSFER
						
						else if (OTItem::transfer == pOriginalItem->GetType())
						{
							// pItem contains the current user's attempt to accept the transfer located in theOriginalItem.
							// Now we have both items.
							OTIdentifier IDFromAccount(pOriginalItem->GetPurportedAccountID());
							OTIdentifier IDToAccount(pOriginalItem->GetDestinationAcctID());
							
							// I'm using the operator== because it exists.
							// If the ID on the "To" account from the original transaction does not
							// match the Acct ID of the client trying to accept the transaction...
							if (!(ACCOUNT_ID == IDToAccount))
							{
								OTLog::Error("Error: Destination account ID on the transaction does not match account ID of client transaction item.\n");
							} 
							
							// -------------------------------------------------------------------
							
							// The 'from' outbox is loaded to remove the outgoing transfer, since it has been accepted.
							// The 'from' inbox is loaded in order to put a notice of this acceptance for the sender's records.
							OTLedger	theFromOutbox(IDFromAccount, SERVER_ID),	// Sender's *OUTBOX*
										theFromInbox(IDFromAccount, SERVER_ID);		// Sender's *INBOX*
							
							bool bSuccessLoadingInbox	= theFromInbox.LoadInbox();
							bool bSuccessLoadingOutbox	= theFromOutbox.LoadOutbox();
							
							// --------------------------------------------------------------------
							
							// THE FROM INBOX -- We are adding an item here (acceptance of transfer),
							// so we will create this inbox if we have to, so we can add that record to it.
							
							if (true == bSuccessLoadingInbox)
								bSuccessLoadingInbox	= theFromInbox.VerifyAccount(m_nymServer);
							else
								bSuccessLoadingInbox	= theFromInbox.GenerateLedger(IDFromAccount, SERVER_ID, OTLedger::inbox, true); // bGenerateFile=true
							
							
							// --------------------------------------------------------------------
							
							// THE FROM OUTBOX -- We are removing an item, so this outbox SHOULD already exist.
							
							if (true == bSuccessLoadingOutbox)
								bSuccessLoadingOutbox	= theFromOutbox.VerifyAccount(m_nymServer);
							else // If it does not already exist, that is an error condition. For now, log and fail.
								OTLog::Error("ERROR missing 'from' outbox in OTServer::NotarizeProcessInbox.\n");
							
							
							// ---------------------------------------------------------------------
							
							if (false == bSuccessLoadingInbox || false == bSuccessLoadingOutbox)
							{
								OTLog::Error("ERROR loading 'from' inbox or outbox in OTServer::NotarizeProcessInbox.\n");
							}
							else 
							{
								// Generate a new transaction number for the sender's inbox (to notice him of acceptance.)
								long lNewTransactionNumber;
								IssueNextTransactionNumber(m_nymServer, lNewTransactionNumber, false); // bStoreTheNumber = false
								
								// Generate a new transaction... (to notice the sender of acceptance.)
								OTTransaction * pInboxTransaction	= OTTransaction::GenerateTransaction(theFromInbox, OTTransaction::pending,
																										 lNewTransactionNumber);
								
								// Here we give the sender (by dropping into his inbox) a copy of my acceptance of
								// his transfer, including the transaction number of my acceptance of his transfer.
								pInboxTransaction->SetReferenceString(strInReferenceTo);
								pInboxTransaction->SetReferenceToNum(pItem->GetTransactionNum());	// Right now this has the 'accept the transfer' transaction number.
																									// It could be changed to the original transaction number, as a better
																									// receipt for the original sender. TODO? Decisions....
								
								// Now we have created a new transaction from the server to the sender's inbox
								// Let's sign it and add to his inbox.
								pInboxTransaction->SignContract(m_nymServer);
								pInboxTransaction->SaveContract();
								
								// At this point I have theInbox ledger, theFromOutbox ledger, theFromINBOX ledger,
								// and theAccount.  So I should remove the appropriate item from each ledger, and
								// add the acceptance to the sender's inbox, and credit the account....
								
								// First try to credit the amount to the account...
								if (theAccount.Credit(pOriginalItem->m_lAmount))
								{
									// Add the "accept" transaction to the sender's inbox 
									// (to notify him that his transfer was accepted.)
									//
									theFromInbox.	AddTransaction(*pInboxTransaction);								
									
									// The original item carries the transaction number that the original
									// sender used to generate the transfer in the first place. This is the number
									// by which that transaction is available in the sender's outbox.
									//
									// Then ANOTHER transaction was created, by the server, in order to put
									// a pending transfer into the recipient's inbox. This has its own transaction
									// number, generated by the server at that time.
									//
									// So we remove the original transfer from the sender's outbox using the
									// transaction number on the original item, and we remove the pending transfer
									// from the recipient's inbox using the transaction number from the pending
									// transaction.
									
									// UPDATE: These two transactions correspond to each other, so I am now creating
									// them with the same transaction number. As you can see, this makes them easy
									// to remove as well.
									theFromOutbox.	RemoveTransaction(pServerTransaction->GetTransactionNum());
									theInbox.		RemoveTransaction(pServerTransaction->GetTransactionNum());
									
									// Release any signatures that were there before (Old ones won't
									// verify anymore anyway, since the content has changed.)
									theInbox.		ReleaseSignatures();
									theAccount.		ReleaseSignatures();
									theFromInbox.	ReleaseSignatures();
									theFromOutbox.	ReleaseSignatures();
									
									// Sign all of them.
									theInbox.		SignContract(m_nymServer);
									theAccount.		SignContract(m_nymServer);
									theFromInbox.	SignContract(m_nymServer);
									theFromOutbox.	SignContract(m_nymServer);
									
									theInbox.		SaveContract();
									theAccount.		SaveContract();
									theFromInbox.	SaveContract();
									theFromOutbox.	SaveContract();
									
									// Save all of them.
									theInbox.		SaveInbox();
									theAccount.		SaveAccount();
									theFromInbox.	SaveInbox();
									theFromOutbox.	SaveOutbox();
									
									// Now we can set the response item as an acknowledgment instead of the default (rejection)
									// otherwise, if we never entered this block, then it would still be set to rejection, and the
									// new items would never have been added to the inbox/outboxes, and those files, along with
									// the account file, would never have had their signatures released, or been re-signed or 
									// re-saved back to file.  The debit failed, so all of those other actions would fail also.
									// BUT... if the message comes back with ACKNOWLEDGMENT--then all of these actions must have
									// happened, and here is the server's signature to prove it.
									// Otherwise you get no items and no signature. Just a rejection item in the response transaction.
									pResponseItem->m_Status	= OTItem::acknowledgement;
								}
								else {
									delete pInboxTransaction; pInboxTransaction = NULL;
									OTLog::Error("Unable to credit account in OTServer::NotarizeProcessInbox.\n");
								}
							} // outbox was successfully loaded
						}// its type is OTItem::transfer
						
						
						
						// -------Cleanup ---------------------------------------
						
						delete pOriginalItem;
						pOriginalItem = NULL;
						
					}// loaded original item from string
					else {
						OTLog::Error("Error loading original item from inbox transaction.\n");
					}					
				}
				else {
					OTLog::vError("Error finding original transaction that client is trying to accept: %ld\n",
							pItem->GetReferenceToNum());
				}
				
				// sign the response item before sending it back (it's already been added to the transaction above)
				// Now, whether it was rejection or acknowledgment, it is set properly and it is signed, and it
				// is owned by the transaction, who will take it from here.
				pResponseItem->SignContract(m_nymServer);
				pResponseItem->SaveContract();
				
				// Just to be safe, I'm updating/signing the outgoing transaction message
				// whenever a response item has just been signed. (Normally this is where
				// this response item would be added to the transaction as well, but I chose
				// to add it at the time it was constructed, so the transaction could be sure
				// to take care of destruction.
				tranOut.ReleaseSignatures();
				tranOut.SignContract(m_nymServer);
				tranOut.SaveContract();
			}

			else {
				OTLog::Error("Error, unexpected OTItem::itemType in OTServer::NotarizeProcessInbox\n");
			} // if type == ACCEPT
		} // if pItem
	} // for each item
}





void OTServer::Init()
{
	// In this implementation, the ServerID is already set in the constructor.
	// So we just want to call this function once in order to make sure that the
	// Nym is loaded up and ready for use decrypting messages that are sent to it.
	// If you comment this out, the server will be unable to decrypt and open envelopes.
	ValidateServerIDfromUser(m_strServerID);
	
	// Load up the transaction number.
	LoadMainFile();
	
	// With the Server's private key loaded, and the latest transaction number loaded,
	// the server is now ready for operation!
}



bool OTServer::ValidateServerIDfromUser(OTString & strServerID)
{
	static bool bFirstTime = true;
	
	if (bFirstTime)
	{
		bFirstTime=false;
		
		// This part is now done when the server XML file is first loaded
//		if (!m_nymServer.Loadx509CertAndPrivateKey())
//		{
//			OTLog::Error("Error loading server certificate and keys.\n");
//		}
//		else {
//			OTLog::Error("Success loading server certificate and keys.\n");
//		}

		//TODO..  Notice after calling Loadx509CertAndPrivateKey, I do not call
		// VerifyPseudonym immediately after, like the client does. That's because
		// the client's ID is a hash of his public key, so that function compares
		// the two.
		//
		// But the server ID is a hash of the SERVER CONTRACT. Which will NOT match
		// the hash of the server public key.
		//
		// Ideally the server will load the contract, and then EXTRACT the public key
		// from the contract, and then use it to verify the signature on the contract,
		// and THEN hash the contract, to get the ServerID, 
		
		// Here's basically what I need to add:  m_ServerContract
		// 
		// ServerContract.SetFilename("server contract file")
		// ServerContract.LoadContract()
		// ServerContract.VerifyContractID()
		// if (success)
		//    ServerContract.VerifySignature(m_nymServer);
		// if (success)
		//    SUCCESS LOADING SERVER CERTIFICATES AND KEYS.
	}
	
	
	if (m_strServerID == strServerID)
	{
		return true;
	}
	
	return false;
}	
		
		
// TODO: Load the actual Server Contract on the Server Side.
// Can do this using existing OTContract class.
// In the meantime, we only support one (test) server contract.
OTServer::OTServer()
{
	// This is hardcoded here, but I believe that after this, I am now actually loading
	// the server ID from the server XML file.
	// Theoretically, if I ever have the change the server ID, I can just change it there now,
	// and it will work. When that happens, I can go ahead and remove the below initialization.
//	m_strServerID = "0bb39523d6b54381c5477aeae808cb51dfbada7bd256e3a0298273a59772f5ad93cd5dee4e6061283dcffd1447719d96fd00b81b8945d01430fdfe68d8adb51f";
//	m_nymServer.SetIdentifier(m_strServerID);

	// This will be set when the server main xml file is loaded. For now, initialize to 0.
	m_lTransactionNumber = 0;
}

OTServer::~OTServer()
{

}
		
bool OTServer::ProcessUserCommand(OTClientConnection & theConnection, OTMessage & theMessage, OTMessage & msgOut)
{	
	// Validate the server ID, to keep users from intercepting a valid requst
	// and sending it to the wrong server.
	if (false == ValidateServerIDfromUser(theMessage.m_strServerID))
	{
		OTLog::Error("Invalid server ID sent in command request.\n");
		return false;
	}
	else {
		OTLog::Error("Received valid Server ID with command request.\n");
	}

	OTPseudonym theNym(theMessage.m_strNymID);
	
	//**********************************************************************************************
	 
	// This command is special because the User sent his public key, not just his ID.
	// We have to verify the two together.
	//
	// At this point the user doesn't even have an account, so there is no public key
	// to look up from the database.
	//
	// If the ServerID in the reply matches the ID calculated from the Server Contract,
	// that means the user, without asking for the server's public key, can just extract
	// the public key from the contract from which the serverID was first calculated. (The
	// ID is a hash of the contract.)
	//
	// In other words, the user reads a contract. It's signed. The signature is verified
	// by a public key that is embedded in the contract. If the server, a URL also embedded in
	// the contract, acknowledges the ServerID, then the user can encrypt everything to the
	// public key in the contract, without asking the server for a copy of that key.
	//
	// Only the private key who signed that contract will be able to read the communications from
	// the user.
	//
	// I definitely have to build in an option for x509 certs to be used in lieu of public keys.
	// Otherwise the key is not ever revokable -- yet it's in a contract!  What is the issuer supposed
	// to do if that key is stolen? Make a public announcement?
	//
	// In such a case, the issuer would have to put a "check this URL to make sure contract still good"
	// variable into the contract so that the users have the chance to make sure the contract is still
	// good and the contract's private key hasn't been stolen. Well guess what? That's what x509 does.
	// Therefore the appropriate solution is for the server to support x509s, and to look up the authority
	// and verify certs, so that users have recourse in the event their private key is stolen. (They can
	// just use their Cert to issue a new public key, which the transaction server would be smart enough
	// to use, once the certificate authority signs off on it. (Since the user uses an x509 from a 
	// specific authority, then I can trust that whatever that authority says, that user wanted it to say.)
	// Without knowing the authority itself, I can now trust it because the user has asked me to trust it.
	// Fair enough!
	//
	// Similarly a user should be able to use his x509 Cert instead of his public key, and the server
	// should verify that cert whenever it's used to make sure it's up to date.  This takes the
	// problem off of the user's hands by way of a trusted authority.
	//
	// In fact this transaction server is really just a transaction VERIFIER. It's just another form
	// of trusted 3rd party. Just like Verisign is an authority who ceritifies an identity, so this
	// server is an authority who certifies a transaction. It's like a timestamping server. In fact
	// it should have timestamping built in as one of the functions.
	//
	// Transactions do not actually occur on the server, per se. They occur between the USERS.
	// All the server does it certify that the numbers are correct. It's like accounting software.
	// Ultimately the users are the ones making a transaction, and they are the ones who are 
	// responsible to back up their promises in real life and potentially in court. All the software
	// does is CERTIFY that the users DID make certain agreements at certain times, and digitally sign
	// those certifications.
	//
	// Thus, this server is very similar to Verisign. It is a trusted 3rd party who users can trust
	// to authenticate their transactions. Instead of authenticating certifications like Verisign does,
	// it authenticates transactions.
	//
	// UPDATE: May not want x509's after all, since it provides an opening for governments to 
	// serve warrants on the authority site and switch certs whenever they want to (BAD THING!)
	//
	if (theMessage.m_strCommand.Compare("checkServerID"))
	{
		OTLog::vOutput(0, "\n==> Received a checkServerID message. Processing...\n");
		
		OTAsymmetricKey & nymPublicKey = (OTAsymmetricKey &)theNym.GetPublicKey();
		
		bool bIfNymPublicKey = 
		nymPublicKey.SetPublicKey(theMessage.m_strNymPublicKey, true/*bEscaped*/);
		
		if (bIfNymPublicKey)
		{
			// Now the Nym has his public key set. Let's compare it to a hash of his ID (should match)
			if (theNym.VerifyPseudonym())
			{
				OTLog::vOutput(0, "Pseudonym verified! The Nym ID is a perfect hash of the public key.\n");
				
				if (theMessage.VerifySignature(theNym)) 
				{
					OTLog::vOutput(0, "Signature verified! The message WAS signed by "
							"the Nym\'s Private Key.\n");
					
					
					// This is only for verified Nyms, (and we're verified in here!) We do this so that 
					// we have the option later to encrypt the replies back to the client...(using the 
					// client's public key that we set here.)
					theConnection.SetPublicKey(theMessage.m_strNymPublicKey);
					
					
					UserCmdCheckServerID(theNym, theMessage, msgOut);

					return true;
				}
				else 
				{
					OTLog::vOutput(0, "Signature failed!\nThe message was NOT signed by the Nym, OR the "
							"message was changed after signing.\n");
					return false;
				}
				
			}
			else
			{
				OTLog::vOutput(0, "Pseudonym failed to verify. Hash of public key doesn't match "
						"Nym ID that was sent.\n");
				return false;
			}
		}
		else {
			OTLog::Error("Failure reading Nym's public key from message.\n");
			return false;
		}
	}
	
	// This command is also special because again, the User sent his public key, not just his ID.
	// We have to verify the two together.
	else if (theMessage.m_strCommand.Compare("createUserAccount"))
	{
		OTLog::Output(0, "\n==> Received a createUserAccount message. Processing...\n");
		
		OTAsymmetricKey & nymPublicKey = (OTAsymmetricKey &)theNym.GetPublicKey();
		bool bIfNymPublicKey = 
		nymPublicKey.SetPublicKey(theMessage.m_strNymPublicKey, true/*bEscaped*/);
		
		if (bIfNymPublicKey)
		{
			// Now the Nym has his public key set. Let's compare it to a hash of his ID (should match)
			if (theNym.VerifyPseudonym())
			{
				OTLog::Output(0, "Pseudonym verified! The Nym ID is a perfect hash of the public key.\n");
				
				if (theMessage.VerifySignature(theNym)) 
				{
					OTLog::Output(0, "Signature verified! The message WAS signed by "
							"the Nym\'s Private Key.\n");
					//
					// Look up the NymID and see if it's already a valid user account.
					// 
					// If it is, then we can't very well create it twice, can we?
					theNym.SetIdentifier(theMessage.m_strNymID);
					
					OTLog::Output(0, "Verifying that account doesn't already exist...\n");

					// Prepare to send success or failure back to user.
					// (1) set up member variables 
					msgOut.m_strCommand		= "@createUserAccount";	// reply to createUserAccount
					msgOut.m_strNymID		= theMessage.m_strNymID;	// UserID
					msgOut.m_strServerID	= m_strServerID;	// ServerID, a hash of the server contract.
					msgOut.m_bSuccess		= false;
					
					// We send the user's message back to him, ascii-armored,
					// as part of our response.
					OTString tempInMessage;
					theMessage.SaveContract(tempInMessage);
					msgOut.m_ascInReferenceTo.SetString(tempInMessage);
					

					if (false == theNym.LoadSignedNymfile(m_nymServer) && false == theNym.LoadPublicKey())
					{
						// Good -- this means the account doesn't already exist.
						// Let's create it.
						OTString strPath;
						strPath.Format((char*)"%s%suseraccounts%s%s", OTLog::Path(), OTLog::PathSeparator(), 
									   OTLog::PathSeparator(), theMessage.m_strNymID.Get());
						
						// First we save the createUserAccount message in the accounts folder...
						if (msgOut.m_bSuccess = theMessage.SaveContract(strPath.Get()))
						{
							OTLog::Output(0, "Success saving new user account verification file.\n");
							
							strPath.Format((char*)"%s%spubkeys%s%s", OTLog::Path(), OTLog::PathSeparator(), 
										   OTLog::PathSeparator(), theMessage.m_strNymID.Get());
							
							// Next we save the public key in the pubkeys folder...
							if (msgOut.m_bSuccess = theNym.SavePublicKey(strPath))
							{
								OTLog::vOutput(0, "Success saving new nym\'s public key file.\n");
								
//								strPath.Format((char*)"%s%snyms%s%s", OTLog::Path(), OTLog::PathSeparator(), 
//											   OTLog::PathSeparator(), theMessage.m_strNymID.Get());
//								if (msgOut.m_bSuccess = theNym.SavePseudonym(strPath.Get()))
								if (msgOut.m_bSuccess = theNym.SaveSignedNymfile(m_nymServer))
								{
									// Set up his very first request number, here on the server
									// with our very own server ID, then let's create him his first request number for him.
									//theNym.IncrementRequestNum(m_strServerID);
									// commented this out because it's below now.
									
									OTLog::vOutput(0, "Success saving new Nymfile. (User account fully created.)\n");

									// This is only for verified Nyms, (and we're verified in here!) We do this so that 
									// we have the option later to encrypt the replies back to the client...(using the 
									// client's public key that we set here.)
									theConnection.SetPublicKey(theMessage.m_strNymPublicKey);
									
									// (2) Sign the Message 
									msgOut.SignContract(m_nymServer);		
									
									// (3) Save the Message (with signatures and all, back to its internal member m_strRawFile.)
									//
									// FYI, SaveContract takes m_xmlUnsigned and wraps it with the signatures and ------- BEGIN  bookends
									// If you don't pass a string in, then SaveContract saves the new version to its member, m_strRawFile
									msgOut.SaveContract();

									return true;
								}
								else 
								{
									// (2) Sign the Message 
									msgOut.SignContract(m_nymServer);		
									
									// (3) Save the Message
									msgOut.SaveContract();

									return true;
								}
							}
							else
							{
								OTLog::Error("Error saving new user account verification file.\n");
								// (2) Sign the Message 
								msgOut.SignContract(m_nymServer);		
								
								// (3) Save the Message 
								msgOut.SaveContract();
								
								return true;
							}
						}
						else {
							OTLog::Error("Error creating Account in OTServer::ProcessUserCommand.\n");
							// (2) Sign the Message 
							msgOut.SignContract(m_nymServer);		
							
							// (3) Save the Message 
							msgOut.SaveContract();
							
							return true;
						}
					}
					else
					{
						OTLog::vOutput(0, "Error: User attempted to create account that already exists: %s\n", 
								theMessage.m_strNymID.Get());
						// (2) Sign the Message 
						msgOut.SignContract(m_nymServer);		
						
						// (3) Save the Message
						msgOut.SaveContract();
						
						return true;
					}

					return true;
				}
				else 
				{
					OTLog::Output(0, "Signature failed!\nThe message was NOT signed by the Nym, OR the "
							"message was changed after signing.\n");
					return false;
				}
				
			}
			else
			{
				OTLog::Output(0, "Pseudonym failed to verify. Hash of public key doesn't match "
						"Nym ID that was sent.\n");
				return false;
			}
		}
		else {
			OTLog::Error("Failure reading Nym's public key from message.\n");
			return false;
		}
	}

	
	// ------------------------------------------------------------------------------------------
	
		
	// Look up the NymID and see if it's a valid user account.
	// 
	// If we didn't receive a public key (above)
	// Or read one from our files (below)
	// ... then we'd have no way of validating the requests.
	//
	// If it is, then we read the public key from that Pseudonym and use it to verify any
	// requests bearing that NymID.
	
	// I appear to already be setting this variable near the top of the function.
	// No idea why I'm setting it twice, probably an oversight. TODO: remove.
	theNym.SetIdentifier(theMessage.m_strNymID);
	
	// For special cases where the Nym sending the transaction has the same public key as
	// the server itself. (IE it IS the server Nym, then we'd want to use the already-loaded
	// server nym object instead of loading a fresh one, so the two don't overwrite each other.)
	//
	bool bNymIsServerNym = (m_strServerUserID.Compare(theMessage.m_strNymID) ? true : false);
	OTPseudonym * pNym = &theNym;
	
	if (bNymIsServerNym)
		pNym = &m_nymServer;
	
	if (!bNymIsServerNym && (false == theNym.LoadPublicKey()))
	{
		OTLog::vError("Failure loading Nym public key: %s\n", theMessage.m_strNymID.Get());
		return false;
	}
	
	// Okay, the file was read into memory and Public Key was successfully extracted!
	// Next, let's use that public key to verify (1) the NymID and (2) the signature
	// on the message that we're processing.

	if (pNym->VerifyPseudonym())
	{
		OTLog::Output(0, "Pseudonym verified! The Nym ID is a perfect hash of the public key.\n");
		
		// So far so good. Now let's see if the signature matches...
		if (theMessage.VerifySignature(*pNym)) 
		{
			OTLog::Output(0, "Signature verified! The message WAS signed by "
					"the Nym\'s Private Key.\n");
			
			// Now we might as well load up the rest of the Nym.
			// Notice I use the || to only load the nymfile if it's NOT the server Nym.
			if (bNymIsServerNym || theNym.LoadSignedNymfile(m_nymServer))
			{
				OTLog::Output(1,  "Successfully loaded Nymfile into memory.\n");
				
				// *****************************************************************************
				// ENTERING THE INNER SANCTUM OF SECURITY. If the user got all the way to here,
				// Then he has passed multiple levels of security, and all commands below will
				// assume the Nym is secure, validated, and loaded into memory for use.
				//
				// But still need to verify the Request Number for all other commands except 
				// Get Request Number itself...
				// *****************************************************************************
				
				// Request numbers start at 1 (currently).
				long lRequestNumber = 0;
				
				if (false == pNym->GetCurrentRequestNum(m_strServerID, lRequestNumber))
				{
					OTLog::Output(0, "Nym file request number doesn't exist. Apparently first-ever request to server--but everything checks out. "
							"(Shouldn't this request number have been created already when the NymFile was first created???????\n");
					// FIRST TIME!  This account has never before made a single request to this server.
					// The above call always succeeds unless the number just isn't there for that server.
					// Therefore, since it's the first time, we'll create it now:
					pNym->IncrementRequestNum(m_nymServer, m_strServerID);

					// Call it again so that lRequestNumber is set to 1 also
					if (pNym->GetCurrentRequestNum(m_strServerID, lRequestNumber))
					{
						OTLog::Output(0, "Created first request number in Nym file, apparently first-ever request. "
								"(Shouldn't this have been created already when the NymFile was first created???????\n");
					}
					else {
						OTLog::Error("ERROR creating first request number in Nym file.\n");	
						return false;
					}
				}
				
				// At this point, I now have the current request number for this nym in lRequestNumber
				// Let's compare it to the one that was sent in the message... (This prevents attackers 
				// from repeat-sending intercepted messages to the server.)
				if (false == theMessage.m_strCommand.Compare("getRequest"))		   // IF it's NOT a getRequest CMD, (therefore requires a request number)
				{
					if (lRequestNumber != atol(theMessage.m_strRequestNum.Get()))  // AND the request number attached does not match what we just read out of the file...
					{
						OTLog::vOutput(0, "Request number sent in this message %ld does not match the one in the file! (%ld)\n",
								atol(theMessage.m_strRequestNum.Get()), lRequestNumber);
						return false;
					}
					else // it's not a getRequest CMD, and the request number sent DOES match what we read out of the file!!
					{
						OTLog::vOutput(0, "Request number sent in this message %ld DOES match the one in the file!\n", lRequestNumber);
						
						// At this point, it is some OTHER command (besides getRequest)
						// AND the request number verifies, so we're going to increment
						// the number, and let the command process.
						pNym->IncrementRequestNum(m_nymServer, m_strServerID);
						
						// *****************************************************************************
						// **INSIDE** THE INNER SANCTUM OF SECURITY. If the user got all the way to here,
						// Then he has passed multiple levels of security, and all commands below will
						// assume the Nym is secure, validated, and loaded into memory for use. They can
						// also assume that the request number has been verified on this message.
						// EVERYTHING checks out.
						// *****************************************************************************
						
						// NO RETURN HERE!!!! ON PURPOSE!!!!
					}

				}
				else  // If you entered this else, that means it IS a getRequest command 
					  // So we allow it to go through without verifying this step, and without incrementing the counter.
				{
					//pNym->IncrementRequestNum(m_strServerID); // commented out cause this is the one case where we DON'T increment this number.
														   // We allow the user to get the number, we DON'T increment it, and now the user
														   // can send it on his next request for some other command, and it will verify 
														   // properly. This prevents repeat messages.

					// NO RETURN HERE!!!! ON PURPOSE!!!!
				}

					
				// At this point, we KNOW that it is EITHER a GetRequest command, which doesn't require a request number,
				// OR it was some other command, but the request number they sent in the command MATCHES the one that we
				// just read out of the file.
				
				// Therefore, we can process ALL messages below this 
				// point KNOWING that the Nym is properly verified in all ways.
				// No messages need to worry about verifying the Nym, or about 
				// dealing with the Request Number. It's all handled in here.
				

				
				// Get the public key from theNym, and set it into the connection.
				// This is only for verified Nyms, (and we're verified in here!) We do this so that 
				// we have the option later to encrypt the replies back to the client...(using the 
				// client's public key that we set here.)
				theConnection.SetPublicKey(pNym->GetPublicKey());
			}
			else {
				OTLog::vError("Error loading Nymfile: %s\n", theMessage.m_strNymID.Get());
				return false;
			}

		}
		else 
		{
			OTLog::Output(0, "Signature failed!\nThe message was NOT signed by the Nym, OR the "
					"message was changed after signing.\n");
			return false;
		}
		
	}
	else
	{
		OTLog::Output(0, "Pseudonym failed to verify. Hash of public key doesn't match "
				"Nym ID that was sent.\n");
		return false;
	}
	
	
	// ----------------------------------------------------------------------------------------
	
	
	// If you made it down this far, that means the Pseudonym verifies! The message is legit.
	//
	// (Server ID was good, NymID is a valid hash of User's public key, and the Signature on
	// the message was signed by the user's private key.)
	//
	// Now we can process the message.
	//
	// All the commands below here, it is assumed that the user account exists and is
	// referenceable via theNym. (An OTPseudonym object.)
	//
	// ALL commands below can assume the Nym is real, and that the NymID and Public Key are
	// available for use -- and that they verify -- without having to check again and again.
	
	
	if (theMessage.m_strCommand.Compare("getRequest")) // This command is special because it's the only one that doesn't require a request number.
													   // All of the other commands, below, will fail above if the proper request number isn't included
													   // in the message.  They will already have failed by this point if they didn't verify.
	{
		OTLog::Output(0, "\n==> Received a getRequest message. Processing...\n");
		
		UserCmdGetRequest(*pNym, theMessage, msgOut);
		
		return true;
	}
	else if (theMessage.m_strCommand.Compare("getTransactionNum"))
	{
		OTLog::Output(0, "\n==> Received a getTransactionNum message. Processing...\n");
		
		UserCmdGetTransactionNum(*pNym, theMessage, msgOut);
		
		return true;
	}
	else if (theMessage.m_strCommand.Compare("checkUser"))
	{
		OTLog::Output(0, "\n==> Received a checkUser message. Processing...\n");
		
		UserCmdCheckUser(*pNym, theMessage, msgOut);
		
		return true;
	}
	else if (theMessage.m_strCommand.Compare("createAccount"))
	{
		OTLog::Output(0, "\n==> Received a createAccount message. Processing...\n");
		
		UserCmdCreateAccount(*pNym, theMessage, msgOut);
		
		return true;
	}
	else if (theMessage.m_strCommand.Compare("issueAssetType"))
	{
		OTLog::Output(0, "\n==> Received an issueAssetType message. Processing...\n");
		
		UserCmdIssueAssetType(*pNym, theMessage, msgOut);
		
		return true;
	}
	else if (theMessage.m_strCommand.Compare("issueBasket"))
	{
		OTLog::Output(0, "\n==> Received an issueBasket message. Processing...\n");
		
		UserCmdIssueBasket(*pNym, theMessage, msgOut);
		
		return true;
	}
	else if (theMessage.m_strCommand.Compare("exchangeBasket"))
	{
		OTLog::Output(0, "\n==> Received an exchangeBasket message. Processing...\n");
		
		UserCmdExchangeBasket(*pNym, theMessage, msgOut);
		
		return true;
	}
	else if (theMessage.m_strCommand.Compare("notarizeTransactions"))
	{
		OTLog::Output(0, "\n==> Received a notarizeTransactions message. Processing...\n");
		
		UserCmdNotarizeTransactions(*pNym, theMessage, msgOut);
		
		return true;
	}
	else if (theMessage.m_strCommand.Compare("getInbox"))
	{
		OTLog::Output(0, "\n==> Received a getInbox message. Processing...\n");
		
		UserCmdGetInbox(*pNym, theMessage, msgOut);
		
		return true;
	}
	else if (theMessage.m_strCommand.Compare("processInbox"))
	{
		OTLog::Output(0, "\n==> Received a processInbox message. Processing...\n");
		
		UserCmdProcessInbox(*pNym, theMessage, msgOut);
		
		return true;
	}
	else if (theMessage.m_strCommand.Compare("getAccount"))
	{
		OTLog::Output(0, "\n==> Received a getAccount message. Processing...\n");
		
		UserCmdGetAccount(*pNym, theMessage, msgOut);
		
		return true;
	}
	else if (theMessage.m_strCommand.Compare("getContract"))
	{
		OTLog::Output(0, "\n==> Received a getContract message. Processing...\n");
		
		UserCmdGetContract(*pNym, theMessage, msgOut);
		
		return true;
	}
	else if (theMessage.m_strCommand.Compare("getMint"))
	{
		OTLog::Output(0, "\n==> Received a getMint message. Processing...\n");
		
		UserCmdGetMint(*pNym, theMessage, msgOut);
		
		return true;
	}
	else
	{
		OTLog::vError("Unknown command type in the XML, or missing payload, in ProcessMessage.\n");
		return false;
	}
}














































































