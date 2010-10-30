/************************************************************************************
 *    
 *  OTCheque.h
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

#ifndef __OT_CHEQUE_H__
#define __OT_CHEQUE_H__


#include <fstream>


#include "OTTrackable.h"
#include "OTIdentifier.h"
#include "OTString.h"



class OTCheque : public OTTrackable
{
protected:
	virtual int ProcessXMLNode(irr::io::IrrXMLReader*& xml);

	long			m_lAmount;
	OTString		m_strMemo;
	OTIdentifier	m_RECIPIENT_USER_ID;// Optional. If present, must match depositor's user ID.
	bool			m_bHasRecipient;
	
public:
	inline void				SetAsVoucher() { m_strContractType = "VOUCHER"; }
	inline OTString &		GetMemo() { return m_strMemo; }
	inline const long &		GetAmount() const { return m_lAmount; }
	inline OTIdentifier &	GetRecipientUserID()	{ return m_RECIPIENT_USER_ID; }
	inline bool				HasRecipient() const { return m_bHasRecipient; }

	
	// Calling this function is like writing a check...
	bool IssueCheque(const long	& lAmount,	const long & lTransactionNum,
					 const time_t & VALID_FROM, const time_t & VALID_TO,// The expiration date (valid from/to dates) of the cheque
					 const OTIdentifier & SENDER_ACCT_ID,			// The asset account the cheque is drawn on.
					 const OTIdentifier & SENDER_USER_ID,			// This ID must match the user ID on the asset account, 
																	// AND must verify the cheque signature with that user's key.
					 const OTString & strMemo,	// Optional memo field.
					 const OTIdentifier * pRECIPIENT_USER_ID=NULL);	// Recipient optional. (Might be a blank cheque.)

	// From OTTrackable (parent class of this)
	/*
	 // A cheque can be written offline, provided you have a transaction
	 // number handy to write it with. (Necessary to prevent double-spending.)
	 inline long			GetTransactionNum() const { return m_lTransactionNum; }
	 inline const OTIdentifier &	GetSenderAcctID()		{ return m_SENDER_ACCT_ID; }
	 inline const OTIdentifier &	GetSenderUserID()		{ return m_SENDER_USER_ID; }
	 */
	
	// From OTInstrument (parent class of OTTrackable, parent class of this)
	/*
	 OTInstrument(const OTIdentifier & SERVER_ID, const OTIdentifier & ASSET_ID) : OTContract()
	 
	 inline const OTIdentifier & GetAssetID() const { return m_AssetTypeID; }
	 inline const OTIdentifier & GetServerID() const { return m_ServerID; }
	 
	 inline time_t GetValidFrom()	const { return m_VALID_FROM; }
	 inline time_t GetValidTo()		const { return m_VALID_TO; }
	 
	 bool VerifyCurrentDate(); // Verify the current date against the VALID FROM / TO dates.
	 */
	OTCheque();
	OTCheque(const OTIdentifier & SERVER_ID, const OTIdentifier & ASSET_ID);
	virtual ~OTCheque();
	
			void InitCheque();
	virtual void Release();
	virtual void UpdateContents(); // Before transmission or serialization, this is where the token saves its contents 	

//	virtual bool SaveContractWallet(FILE * fl);
	virtual bool SaveContractWallet(std::ofstream & ofs);
};


#endif // __OT_CHEQUE_H__






















