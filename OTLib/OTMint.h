/************************************************************************************
 *    
 *  OTMint.h
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

#ifndef __OTMINT_H__
#define __OTMINT_H__

#include <ctime>

#include "OTContract.h"
#include "OTEnvelope.h"
#include "OTASCIIArmor.h"
#include "OTToken.h"
#include "OTAccount.h"


class OTMint : public OTContract
{
protected:
	virtual int ProcessXMLNode(irr::io::IrrXMLReader*& xml);
		
	void InitMint();

	mapOfArmor		m_mapPrivate;	// An ENVELOPE. You need to pass the Pseudonym to every method that uses this. Private.
									// Then you have to set it into an envelope and then open it using the Nym. Encrypted.
	mapOfArmor		m_mapPublic;	// An Ascii-armored string of the mint Public information. Base64-encoded only.
	
	
	OTIdentifier	m_ServerID;		// The Nym ID of the Server, whose public key is m_keyPublic
	OTAsymmetricKey m_keyPublic;	// The server's public key.
	
	OTIdentifier	m_AssetID;		// Each Asset type has its own mint.
	
	int				m_nDenominationCount; // How many denominations of the currency are issued by this Mint?
										  // (Each requires its own key pair.)

	bool			m_bSavePrivateKeys; // Determines whether it serializes private keys (no if true)
	
	
	// --- MINT SERIES with EXPIRATION DATES ------------------
	
	int				m_nSeries;		// Each series of the mint has a valid from and to date. Series should rotate.
									// (That is, the new one should be introduced halfway through the validity period
									// of the current one, and so on...)
	
	time_t			m_VALID_FROM;	// All tokens generated by this series will have the same From and To dates.
	time_t			m_VALID_TO;		// This way they cannot be tracked by expiration date.
	
	time_t			m_EXPIRATION;	// The Mint itself expires before the tokens do. (As the new series rotates in...)
	
	OTIdentifier	m_CashAccountID;// The Account ID for the cash reserve account. (Pointer below.)
	
	OTAccount	*	m_pReserveAcct;	// When you withdraw cash, the Mint removes X dollars from your account, then
									// it puts those X dollars into this reserve account, and then issues you the 
									// blinded tokens. When the tokens are deposited again, the money comes back out
									// of the same reserve account and goes into the depositor's account. This way, 
									// all tokens will have 1-for-1 funds backing them, and any funds left over after
									// the tokens expire, is the server operator's money to keep!
	
public:
	
	inline	int		GetSeries()		const { return m_nSeries; }		// The series ID
	inline	time_t	GetValidFrom()	const { return m_VALID_FROM; }	// The token "valid from" date for this series
	inline	time_t	GetValidTo()	const { return m_VALID_TO; }	// The token "valid until" date for this series
	inline	time_t	GetExpiration()	const { return m_EXPIRATION; }	// The date the mint expires (should be halfway
																	// between the above two dates.)
	bool Expired() const;	// true or false. Expired? 
							// Valid range is GetValidFrom() through GetExpiration().
	
	inline OTAccount * GetCashReserveAccount() const { return m_pReserveAcct; }
	
	OTMint();
	OTMint(const OTString & name, const OTString & filename, const OTString & strID);
	virtual ~OTMint();
	virtual void Release();
	void ReleaseDenominations();
	
	// Will save the private keys on next serialization (not just public keys)
	// (SignContract sets m_bSavePrivateKeys back to false again.)
	inline void SetSavePrivateKeys(bool bDoIt=true) { m_bSavePrivateKeys = bDoIt; }	
	
	
	// The denomination indicated here is the actual denomination...1, 5, 20, 50, 100, etc
	bool GetPrivate(OTASCIIArmor & theArmor, long lDenomination);
	bool GetPublic(OTASCIIArmor & theArmor, long lDenomination);
	
	long GetDenomination(int nIndex);
	long GetLargestDenomination(long lAmount);
	bool AddDenomination(OTPseudonym & theNotary, long lDenomination, int nPrimeLength=1024);
	inline int GetDenominationCount() const { return m_nDenominationCount; }

	virtual bool VerifyContractID();
	
	bool VerifyMint(OTPseudonym & theOperator);
	
	virtual void UpdateContents(); // Before transmission or serialization, this is where the token saves its contents 

	inline void SetAssetID(const OTIdentifier & newID) { m_AssetID = newID; }
	
	// Lucre step 1: generate new mint
	void GenerateNewMint(int nSeries, time_t VALID_FROM, time_t VALID_TO,  time_t MINT_EXPIRATION, 
						 const OTIdentifier & theAssetID, OTPseudonym & theNotary, 
						 long nDenom1=0, long nDenom2=0, long nDenom3=0, long nDenom4=0, long nDenom5=0,
						 long nDenom6=0, long nDenom7=0, long nDenom8=0, long nDenom9=0, long nDenom10=0);

	// step 2: (coin request is in OTToken)
	
	// Lucre step 3: mint signs token
	bool SignToken(OTPseudonym & theNotary, OTToken & theToken, OTString & theOutput, int nTokenIndex);
	
	// step 4: (unblind coin is in OTToken)
	
	// Lucre step 5: mint verifies token when it is redeemed by merchant.
	bool VerifyToken(OTPseudonym & theNotary, OTString & theCleartextToken, long lDenomination);

	virtual bool SaveContractWallet(std::ofstream & ofs);
//	virtual bool SaveContractWallet(FILE * fl);	
};


#endif // __OTMINT_H__
