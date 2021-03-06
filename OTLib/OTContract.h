/************************************************************************************
 *    
 *  OTContract.h
 *  
 *		Open Transactions:  Library, Protocol, Server, and Test Client
 *    
 *    			-- Anonymous Numbered Accounts
 *    			-- Untraceable Digital Cash
 *    			-- Triple-Signed Receipts
 *    			-- Basket Currencies
 *    			-- Signed XML Contracts
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
 *    	  If you would like to use this software outside of the free software
 *    	  license, please contact FellowTraveler.
 *   
 *        This library is also "dual-license", meaning that Ben Laurie's license
 *        must also be included and respected, since the code for Lucre is also
 *        included with Open Transactions.
 *        The Laurie requirements are light, but if there is any problem with his
 *        license, simply remove the Lucre code. Although there are no other blind
 *        token algorithms in Open Transactions (yet), the other functionality will
 *        continue to operate .
 *    
 *    OpenSSL WAIVER:
 *        This program is released under the AGPL with the additional exemption 
 *    	  that compiling, linking, and/or using OpenSSL is allowed.
 *    
 *    DISCLAIMER:
 *        This program is distributed in the hope that it will be useful,
 *        but WITHOUT ANY WARRANTY; without even the implied warranty of
 *        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *        GNU Affero General Public License for more details.
 *    	
 ************************************************************************************/


#ifndef __OTCONTRACT_H__
#define __OTCONTRACT_H__

#include <cstdio>	

extern "C" 
{
#include <openssl/evp.h>	
}

#include <list>
#include <map>
#include <string>
#include <fstream>

#include "irrxml/irrXML.h"

#include "OTIdentifier.h"

#include "OTData.h"
#include "OTString.h"
#include "OTAsymmetricKey.h"

#include "OTSignature.h"
#include "OTStringXML.h"

class OTPseudonym;
class OTIdentifier;


typedef std::list <OTSignature *>				listOfSignatures;
typedef std::map  <std::string, OTPseudonym *>	mapOfNyms;

class OTContract
{
	friend class OTPayload;
	
protected:
	OTString		m_strName;			// Contract name as shown in the wallet.
	OTString		m_strFilename;		// Filename for this contract
	OTIdentifier	m_ID;				// Hash of the contract, including signatures. (the "raw file")
	OTStringXML		m_xmlUnsigned;		// The Unsigned Clear Text (XML contents without signatures.)
	OTString		m_strRawFile;		// The complete raw file including signatures.
	OTString		m_strSigHashType;	// The Hash algorithm used for the signature
	OTString		m_strContractType;	// CONTRACT, MESSAGE, TRANSACTION, LEDGER, TRANSACTION ITEM 

	mapOfNyms		m_mapNyms;	// The default behavior for a contract, though occasionally overridden,
								// is to contain its own public keys internally, located on standard XML tags.
								// 
								// So when we load a contract, we find its public key, and we verify its
								// signature with it. (It self-verifies!) I could be talking about an x509
								// as well, since people will need these to be revokable.
								//
								// The Issuer/Server/etc URL will also be located within the contract, on a
								// standard tag, so by merely loading a contract, a wallet will know how to
								// connect to the relevant server, and the wallet will be able to encrypt
								// messages meant for that server to its public key without the normally requisite
								// key exchange.  ==> THE TRADER HAS ASSURANCE THAT, IF HIS OUT-MESSAGE IS ENCRYPTED,
								// HE KNOWS THE MESSAGE CAN ONLY BE DECRYPTED BY THE SAME PERSON WHO SIGNED THAT CONTRACT.
	
	listOfSignatures	m_listSignatures;  // The PGP signatures at the bottom of the XML file.
	
	OTString		m_strVersion; // The version of this Contract file, in case the format changes in the future.
	
	bool LoadContractXML(); // The XML file is in m_xmlUnsigned. Load it from there into members here.
	
	bool LoadEncodedTextField(irr::io::IrrXMLReader*& xml, OTString &strOutput);
	bool LoadEncodedTextField(irr::io::IrrXMLReader*& xml, OTASCIIArmor &ascOutput);

	// return -1 if error, 0 if nothing, and 1 if the node was processed.
	virtual int ProcessXMLNode(irr::io::IrrXMLReader*& xml);
	
	virtual bool SignContract(const EVP_PKEY * pkey, OTSignature & theSignature,
							  const OTString & strHashType);
	bool VerifySignature(const EVP_PKEY * pkey, const OTSignature & theSignature, 
						 const OTString & strHashType) const;

	// The default hash scheme involves combining 2 other hashes
	// If a hash with one of the special names comes through, it will
	// be processed here instead of the normal code. The above two functions
	// will call these two when appropriate.
	bool SignContractDefaultHash(const EVP_PKEY * pkey, OTSignature & theSignature);
	bool VerifyContractDefaultHash(const EVP_PKEY * pkey, const OTSignature & theSignature) const;

public:
	inline const char * GetHashType() const { return m_strSigHashType.Get(); }
	
	inline void SetIdentifier(const OTIdentifier & theID) { m_ID = theID; }
	
	OTContract();
	OTContract(const OTString & name, const OTString & filename, const OTString & strID);
	OTContract(const OTString & strID);
	OTContract(const OTIdentifier & theID);
 
	void Initialize();
	
	// TODO: a contract needs to have certain required fields in order to be accepted for notarization.
	// One of those should be a URL where anyone can see a list of the approved e-notary servers, signed
	// by the issuer.
	//
	// Why is this important?
	//
	// Because when the issuer connects to the e-notary to issue the currency, he must upload the
	// asset contract as part of that process. During the same process, the e-notary connects to that
	// standard URL and downloads a RECORD, signed by the ISSUER, showing the e-notary on the accepted
	// list of transaction providers.
	//
	// Now the e-notary can make THAT record available to its clients (most likely demanded by their 
	// wallet software) as proof that the issuer has, in fact, issued digital assets on the e-notary
	// server in question. This provides proof that the issuer is, in fact, legally on the line for
	// whatever assets they have actually issued through that e-notary. The issuer can make the total
	// outstanding units available publicly, which wallets can cross-reference with the public records
	// on the transaction servers. (The figures concerning total issued currency should match.)
	//
	// Of course, the transaction server could still lie, and publish a falsified number instead of
	// the actual total issued currency for a given digital asset. Only systems can prevent that, 
	// based around separation of powers. People will be more likely to trust the transaction provider
	// who has good accounting and code audit processes, with code fingerprints, multiple passwords
	// across neutral and bonded 3rd parties, insured, etc.  Ultimately these practices will be 
	// governed by the cost of insurance.
	//
	// But there WILL be winners who arise because they implement systems that provide trust.
	// And trust is a currency.
	//
	// (Currently the code loads the key FROM the contract itself, which won't be possible when
	// the issuer and transaction provider are two separate entities. So this sort of protocol
	// becomes necessary.)
	
	virtual ~OTContract();
	virtual void Release();
	void ReleaseSignatures();

	// This function is for those times when you already have the unsigned version 
	// of the contract, and you have the signer, and you just want to sign it and
	// calculate its new ID from the finished result.
	virtual bool CreateContract(OTString & strContract, OTPseudonym & theSigner);
	
	bool InsertNym(const OTString & strKeyName, const OTString & strKeyValue);

	inline void GetName(OTString & strName) const { strName = m_strName; }
	inline void SetName(const OTString & strName) { m_strName = strName; }

	// This function calls VerifyContractID, and if that checks out, then it looks up the official
	// "contract" key inside the contract by calling GetContractPublicKey, and uses it to verify the
	// signature on the contract. So the contract is self-verifying. Right now only public keys are
	// supported, but soon contracts will also support x509 certs.
	virtual bool VerifyContract();
	
	// Only overriden in OTOffer so far.
	virtual void GetIdentifier(OTIdentifier & theIdentifier);// You can get it in string or binary form.
	virtual void GetIdentifier(OTString & theIdentifier);    // The Contract ID is a hash of the contract raw file.
	
	void GetFilename(OTString & strFilename);
	
	
	// If you have a contract in string form, and you don't know what subclass it is,
	// but you still want to instantiate it, and load it up properly, then call this
	// class method.
	//
	static OTContract * InstantiateContract(OTString & strInputContract);

	
	// assumes m_strFilename is already set. Then it reads that file into a string.
	// Then it parses that string into the object.	
	virtual bool LoadContract();
	bool LoadContract(const char * szFilename);
	
	bool LoadContractFromString(const OTString & theStr); // Just like it says. If you have a contract in
														  // string form, pass it in here to import it.
	bool LoadContractRawFile(); // fopens m_strFilename and reads it off the disk into m_strRawFile
	bool ParseRawFile();		// parses m_strRawFile into the various member variables.
								// Separating these into two steps allows us to load contracts
								// from other sources besides files.
	
	bool SaveToContractFolder(); // data_folder/contracts/Contract-ID

	bool SaveContract(); // This saves the Contract to its own internal member string, m_strRawFile (and does
						 // NOT actually save it to a file.)
	bool SaveContract(OTString & strContract); // Saves the contract to any string you want to pass in.
	bool SaveContract(const char * szFilename); // Saves the contract to its internal member, then saves 
												// that to a specific filename
	
	// Update the internal unsigned contents based on the member variables
	virtual void UpdateContents(); // default behavior does nothing.
	
	// Save the internal contents (m_xmlUnsigned) to an already-open file
//	virtual bool SaveContents(FILE * fl) const;
	virtual bool SaveContents(std::ofstream & ofs) const;
	
	// Saves the entire contract to a file that's already open (like a wallet).
//	virtual bool SaveContractWallet(FILE * fl) = 0;
	virtual bool SaveContractWallet(std::ofstream & ofs) = 0;
	virtual bool SaveContractWallet(OTString & strContents) const;

	virtual bool DisplayStatistics(OTString & strContents) const;

	// Save m_xmlUnsigned to a string that's passed in
	virtual bool SaveContents(OTString & strContents) const;
		
	virtual bool SignContract(const OTPseudonym & theNym);
	
	bool SignContract(const OTPseudonym & theNym, OTSignature & theSignature);
	bool SignContract(const OTAsymmetricKey & theKey, OTSignature & theSignature, 
					  const OTString & strHashType);
	bool SignContract(const char * szFilename, OTSignature & theSignature);
	
	// Calculates a hash of m_strRawFile (the xml portion of the contract plus the signatures)
	// and compares to m_ID (supposedly the same. The ID is calculated by hashing the file.)
	//
	// Be careful here--asset contracts and server contracts can have this ID.
	// But a class such as OTAccount will change in its datafile as the balance
	// changes. Thus, the account must have a Unique ID that is NOT a hash of its file.
	// 
	// This means it's important to have the ID function overridable for OTAccount...
	// This also means that my wallet MUST be signed, and these files should have
	// and encryption option also. Because if someone changes my account ID in the file,
	// I have no way of re-calculating it from the account file, which changes! So my
	// copies of the account file and wallet file are the only records of that account ID
	// which is a giant long number.
	virtual bool VerifyContractID();  
	virtual void CalculateContractID(OTIdentifier & newID) const;
	
	// So far not overridden anywhere (used to be OTTrade.)
	virtual bool VerifySignature(const OTPseudonym & theNym);
	bool VerifySignature(const OTPseudonym & theNym, const OTSignature & theSignature) const;
	bool VerifySignature(const OTAsymmetricKey & theKey, const OTSignature & theSignature,
						 const OTString & strHashType) const;
	bool VerifySignature(const char * szFilename, const OTSignature & theSignature) const;
	
	
	
	//bool VerifySignatures(); // This function verifies the signatures on the contract.
							 // If true, it proves that certain entities really did sign
							 // it, and that the contract hasn't been tampered with since
							 // it was signed.
	const OTAsymmetricKey * GetContractPublicKey();
	const OTPseudonym	  * GetContractPublicNym();	
};

#endif // __OTCONTRACT_H__
