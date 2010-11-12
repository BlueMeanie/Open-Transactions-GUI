
/************************************************************************************
 *    
 *  OTIdentifier.cpp
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



extern "C"
{
#include <openssl/crypto.h>
	
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
	
#ifndef ANDROID // Android thus far only supports OpenSSL 0.9.8k 
#include <openssl/whrlpool.h>
	
	// Just trying to get Whirlpool working since they added it to OpenSSL
	//
	static int init(EVP_MD_CTX *ctx)
	{ return WHIRLPOOL_Init((WHIRLPOOL_CTX*)ctx->md_data); }
	
	static int update(EVP_MD_CTX *ctx,const void *data,size_t count)
	{ return WHIRLPOOL_Update((WHIRLPOOL_CTX*)ctx->md_data,data,count); }
	
	static int final(EVP_MD_CTX *ctx,unsigned char *md)
	{ return WHIRLPOOL_Final(md,(WHIRLPOOL_CTX*)ctx->md_data); }
	
	
	static const EVP_MD whirlpool_md=
	{
		NID_whirlpool,
		0,
		WHIRLPOOL_DIGEST_LENGTH,
		0,
		init,
		update,
		final,
		NULL,
		NULL,
		EVP_PKEY_NULL_method,
		WHIRLPOOL_BBLOCK/8,
		sizeof(EVP_MD *)+sizeof(WHIRLPOOL_CTX),
	};
#endif // ANDROID
	
}

#include <cstdio>
#include <cstring>

#include <iostream>
#include <string>
//#include "cryptopp/hex.h"
//#include "cryptopp/files.h"
//#include "cryptopp/channels.h"

#include "OTData.h"
#include "OTString.h"

#include "OTIdentifier.h"
#include "OTPseudonym.h"
#include "OTContract.h"
#include "OTOffer.h"
#include "OTTrade.h"
#include "OTMarket.h"

#include "OTLog.h"

//using namespace CryptoPP;




OTIdentifier::OTIdentifier() : OTData()
{
	
}


OTIdentifier::OTIdentifier(const char * szStr) : OTData()
{
	SetString(szStr);
}

OTIdentifier::OTIdentifier(const OTString & theStr) : OTData()
{
	SetString((OTString&)theStr);
}

OTIdentifier::OTIdentifier(const OTContract &theContract)  : OTData() // Get the contract's ID into this identifier.
{
	((OTContract &)theContract).GetIdentifier(*this);
}

OTIdentifier::OTIdentifier(const OTPseudonym &theNym)  : OTData() // Get the Nym's ID into this identifier.
{
	((OTPseudonym &)theNym).GetIdentifier(*this);
}

OTIdentifier::OTIdentifier(const OTOffer &theOffer)  : OTData() // Get the Offer's Market ID into this identifier.
{
	((OTOffer &)theOffer).GetIdentifier(*this);
}

OTIdentifier::OTIdentifier(const OTMarket &theMarket)  : OTData() // Get the Market ID into this identifier.
{
	((OTMarket &)theMarket).GetIdentifier(*this);
}



OTIdentifier::~OTIdentifier()
{
	
}

void OTIdentifier::CopyTo(unsigned char * szNewLocation) const
{
	if (GetSize())
	{
		memcpy((void*)GetPointer(), szNewLocation, GetSize());
	}
}




// --------------------
/*
 SHA256_CTX context;
 unsigned char md[SHA256_DIGEST_LENGTH];
 
 SHA256_Init(&context);
 SHA256_Update(&context, (unsigned char*)input, length);
 SHA256_Final(md, &context);
 */
// ----------------------



// On the advice of SAMY, our default hash algorithm will be an XOR
// of two reputable algorithms. This way, if one of them gets broken,
// our signatures are still safe. 
// Smart, eh?  So I named it in his honor.
// (I have chosen SHA-256 and RIPEMD-256.)
//

#ifndef ANDROID
const OTString OTIdentifier::DefaultHashAlgorithm("SAMY");
#else
const OTString OTIdentifier::DefaultHashAlgorithm("SHA512");
#endif // ANDROID

const OTString OTIdentifier::HashAlgorithm1("SHA512");
const OTString OTIdentifier::HashAlgorithm2("WHIRLPOOL");

// I would like to use Tiger and/or Whirlpool in the mix here.
// Unfortunately, OpenSSL does not appear to support them. I may
// try Crypto++ in order to add this functionality.

const EVP_MD * OTIdentifier::GetOpenSSLDigestByName(const OTString & theName) 
{
	if (theName.Compare("SHA1"))
		return EVP_sha1();
	else if (theName.Compare("SHA224"))
		return EVP_sha224();
	else if (theName.Compare("SHA256"))
		return EVP_sha256();
	else if (theName.Compare("SHA384"))
		return EVP_sha384();
	else if (theName.Compare("SHA512"))
		return EVP_sha512();
#ifndef ANDROID
	else if (theName.Compare("WHIRLPOOL"))
		return &whirlpool_md;
#endif
	return NULL;
}
/*
 const EVP_MD * GetDigestByName(const OTString & theName) 
 {
 if (theName.Compare("SHA1"))
 return EVP_sha1();
 else if (theName.Compare("SHA224"))
 return EVP_sha224();
 else if (theName.Compare("SHA256"))
 return EVP_sha256();
 else if (theName.Compare("SHA384"))
 return EVP_sha384();
 else if (theName.Compare("SHA512"))
 return EVP_sha512();
 //	else if (theName.Compare("RMD256"))
 //		return EVP_ripemd256();
 else
 return NULL;
 }
 */


/*
 bool getSHA1Hash(const std::string& p_file, std::string& result, bool p_upperCase) 
 { 
 try 
 { 
 SHA1 hash; 
 FileSource(p_file.c_str(),true, new HashFilter(hash, new HexEncoder(new StringSink(result),p_upperCase))); 
 } 
 catch (const std::exception& e) { 
 return false;
 } 
 return true; 
 } 
 */

/*
 // OpenSSL installed Whirlpool, so I'm going to try their version.
 // The below functions are implemented via Crypto++ by Wei Dai.
 
 // Read a file, digest it with Whirlpool, and store the result inside this object.
 bool OTIdentifier::DigestFileWhirlpool(const OTString& strFilename) 
 { 
 bool bUpperCase = true;
 std::string result;
 
 try 
 { 
 Whirlpool hash; 
 FileSource(strFilename.Get(), true, new HashFilter(hash, 
 new HexEncoder(new StringSink(result), bUpperCase))); 
 } 
 catch (const std::exception& e) { 
 return false;
 } 
 OTString strResult(result.c_str());
 SetString(strResult);
 return true; 
 } 
 
 // Digest a string using Whirlpool and store it in this (as binary hash object)
 bool OTIdentifier::DigestStringWhirlpool(const OTString& theSource) 
 { 
 bool bUpperCase = true;
 std::string result, source=theSource.Get();
 
 try 
 { 
 Whirlpool hash; 
 StringSource(source, true, new HashFilter(hash, 
 new HexEncoder(new StringSink(result),bUpperCase))); 
 } 
 catch (const std::exception& e) { 
 return false;
 } 
 
 OTString strResult(result.c_str());
 SetString(strResult);
 return true; 
 } 
 
 
 // Digest a chunk of binary data and store the result inside this object.
 bool OTIdentifier::DigestBinaryWhirlpool(const OTData& theSource) 
 { 
 bool bUpperCase = true;
 std::string result;
 
 try 
 { 
 Whirlpool hash; 		
 ArraySource((const byte*)theSource.GetPointer(), theSource.GetSize(), true, new HashFilter(hash, 
 new HexEncoder(new StringSink(result),bUpperCase))); 
 } 
 catch (const std::exception& e) { 
 return false;
 } 
 
 OTString strResult(result.c_str());
 SetString(strResult);
 return true; 
 } 
 
 
 void OTIdentifier::DigestStringWhirlpool(const std::string & theSource, std::string & theOutput)
 {
 Whirlpool whirlpool;
 HashFilter theFilter(whirlpool);
 
 ChannelSwitch channelSwitch;
 channelSwitch.AddDefaultRoute(theFilter);
 
 StringSource(theSource, true, &channelSwitch);
 
 HexEncoder encoder(new StringSink(theOutput), false);
 
 OTLog::vError("%s: ", theFilter.AlgorithmName().c_str());
 theFilter.TransferTo(encoder);
 }
 */


/*
 unsigned char *RIPEMD160(const unsigned char *d, unsigned long n,
 unsigned char *md);
 int RIPEMD160_Init(RIPEMD160_CTX *c);
 int RIPEMD160_Update(RIPEMD_CTX *c, const void *data,
 unsigned long len);
 int RIPEMD160_Final(unsigned char *md, RIPEMD160_CTX *c);
 */

/* 
 const OTString OTIdentifier::DefaultHashAlgorithm("SAMY");
 
 const OTString OTIdentifier::HashAlgorithm1("SHA256");
 const OTString OTIdentifier::HashAlgorithm2("RMD256");
 */


// This method implements the SAMY hash
bool OTIdentifier::CalculateDigest(const OTString & strInput)
{
#ifndef ANDROID // SHA512 on Android; no whirlpool until OpenSSL 1.0.0a is added.
	OTIdentifier idSecondHash;
	
	if (idSecondHash.CalculateDigest(strInput, HashAlgorithm2) &&
		CalculateDigest(strInput, HashAlgorithm1))
	{
		// At this point, we have successfully generated the RMD-256 hash in 
		// idSecondHash, and we've successfully generated the SHA-256 hash in 
		// this object.
		// Next we XOR them together for the final product.
		return XOR(idSecondHash);
	}
#else // ANDROID
	if (CalculateDigest(strInput, HashAlgorithm1))
	{
		return true;
	}	
#endif // ANDROID
	
	return false;
}


// This method implements the SAMY hash
bool OTIdentifier::CalculateDigest(const OTData & dataInput)
{
#ifndef ANDROID // SHA512 on Android; no whirlpool until OpenSSL 1.0.0a is added.
	OTIdentifier idSecondHash;
	
	if (idSecondHash.CalculateDigest(dataInput, HashAlgorithm2) &&
		CalculateDigest(dataInput, HashAlgorithm1))
	{
		// At this point, we have successfully generated the RMD-256 hash in 
		// idSecondHash, and we've successfully generated the SHA-256 hash in 
		// this object.
		// Next we XOR them together for the final product.
		return XOR(idSecondHash);
	}
#else // ANDROID
	if (CalculateDigest(dataInput, HashAlgorithm1))
	{
		return true;
	}	
#endif // ANDROID
	
	return false;
}



// Some of the digest calculations are done by crypto++, instead of OpenSSL.
// Also, at least one of the algorithms (SAMY) is an internal name, and again not
// handled by OpenSSL.  So I call this function first to see if the hash type requres
// internal handling. If not, then I return false and the caller knows to use OpenSSL
// instead.
bool OTIdentifier::CalculateDigestInternal(const OTString & strInput, const OTString & strHashAlgorithm)
{
	// See if they wanted to use the SAMY hash
	if (strHashAlgorithm.Compare(DefaultHashAlgorithm)) 
	{
		return CalculateDigest(strInput);
	}
	//	else if (strHashAlgorithm.Compare("WHIRLPOOL"))
	//	{
	//		return DigestStringWhirlpool(strInput);
	//	}
	
	return false;
}


// Some of the digest calculations are done by crypto++, instead of OpenSSL.
// Also, at least one of the algorithms (SAMY) is an internal name, and again not
// handled by OpenSSL.  So I call this function first to see if the hash type requres
// internal handling. If not, then I return false and the caller knows to use OpenSSL
// instead.

bool OTIdentifier::CalculateDigestInternal(const OTData & dataInput, const OTString & strHashAlgorithm)
{
	// See if they wanted to use the SAMY hash
	if (strHashAlgorithm.Compare(DefaultHashAlgorithm)) 
	{
		return CalculateDigest(dataInput);
	}
	//	else if (strHashAlgorithm.Compare("WHIRLPOOL"))
	//	{
	//		return DigestBinaryWhirlpool(dataInput);
	//	}
	
	return false;	
}


// This function lets you choose the hash algorithm by string.
// (For example, if you read "SHA-256" out of a signed file and you
// needed to get the hash function based on that string, you could use this.)
//
bool OTIdentifier::CalculateDigest(const OTString & strInput, const OTString & strHashAlgorithm)
{
	Release();
	
	EVP_MD_CTX mdctx;
	const EVP_MD *md = NULL;
	
	unsigned int md_len = 0;
	unsigned char md_value[EVP_MAX_MD_SIZE];	// I believe this is safe, having just analyzed this function.
	
	// Some hash algorithms are handled by other methods.
	// If those don't handle it, then we'll come back here and use OpenSSL.
	if (CalculateDigestInternal(strInput, strHashAlgorithm))
	{
		return true;
	}
	
	// Okay, it wasn't any internal hash algorithm, so then which one was it?
	md = GetOpenSSLDigestByName(strHashAlgorithm);
	
	if (!md)	
	{
		OTLog::vError("Unknown message digest algorithm in OTIdentifier::CalculateDigest: %s\n", 
				strHashAlgorithm.Get());
		return false;
	}
	
	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, md, NULL);
	EVP_DigestUpdate(&mdctx, strInput.Get(), strInput.GetLength());
	EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
	EVP_MD_CTX_cleanup(&mdctx);
	
	//	OTLog::vError("Calculated %s digest.\n", strHashAlgorithm.Get());
	
	//	for (int i = 0; i < md_len; i++) OTLog::vError("%02x", md_value[i]);
	//	OTLog::Error("\n");
	
	Assign(md_value, md_len);
	
	return true;
}

bool OTIdentifier::CalculateDigest(const OTData & dataInput, const OTString & strHashAlgorithm)
{
	Release();
	
	EVP_MD_CTX mdctx;
	const EVP_MD *md = NULL;
	
	unsigned int md_len = 0;
	unsigned char md_value[EVP_MAX_MD_SIZE];	// I believe this is safe, shouldn't ever be larger than MAX SIZE.
	
	// Some hash algorithms are handled by other methods.
	// If those don't handle it, then we'll come back here and use OpenSSL.
	if (CalculateDigestInternal(dataInput, strHashAlgorithm))
	{
		return true;
	}
	
	// Okay, it wasn't any internal hash algorithm, so then which one was it?
	md = GetOpenSSLDigestByName(strHashAlgorithm);
	
	if (!md) 
	{
		OTLog::vError("Unknown message digest algorithm in OTIdentifier::CalculateDigest: %s\n", 
				strHashAlgorithm.Get());
		return false;
	}
	
	EVP_MD_CTX_init(&mdctx);
	EVP_DigestInit_ex(&mdctx, md, NULL);
	EVP_DigestUpdate(&mdctx, dataInput.GetPointer(), dataInput.GetSize());
	EVP_DigestFinal_ex(&mdctx, md_value, &md_len);
	EVP_MD_CTX_cleanup(&mdctx);
	
	//	OTLog::vOutput(5, "Calculated %s digest.\n", strHashAlgorithm.Get());
	
	//	for (int i = 0; i < md_len; i++) OTLog::vOutput(5, "%02x", md_value[i]);
	//	OTLog::Output(5, "\n");
	
	Assign(md_value, md_len);
	
	return true;
}

// So we can implement the SAMY hash, which is currently an XOR of SHA-256 with RIPEMD-256
bool OTIdentifier::XOR(const OTIdentifier & theInput)
{
	// Go with the smallest of the two
	const long lSize = (GetSize() > theInput.GetSize() ? theInput.GetSize() : GetSize());
	
	for (int i = 0; i < lSize; i++)
	{
		((char*)GetPointer())[i] ^= ((char*)theInput.GetPointer())[i];
	}
	
	return true;
}



union CharToShort
{
	unsigned char c[2];
	unsigned int sh;
};


void OTIdentifier::SetString(const char * szString)
{
	OT_ASSERT(NULL != szString);
	
	const OTString theStr(szString);
	SetString(theStr);
}

//TODO speed this up.
// could be named "set from string" or "set by string"
// Basically so you could take one of the hashes out of the
// xml files, as a string, and plug it in here to get the 
// binary hash back into memory inside this object.
void OTIdentifier::SetString(const OTString & theStr)
{	
	
	Release();
	
	if (!theStr.GetLength())
		return;
	
	if (128 != theStr.GetLength())
	{
		OTLog::Error("String wrong length to convert to ID.\n");
		return;
	}
	
	OTString & refString = (OTString&)theStr;
	
	char c = 0;
	char d = 0;
	
	char ca[3] = "";
	
	static unsigned char * tempArray = NULL;
	
	if (NULL == tempArray)
	{
		tempArray = new unsigned char[MAX_STRING_LENGTH];
		
		OT_ASSERT(NULL != tempArray);
	}
	
	tempArray[0] = '\0';
	
	unsigned int shTemp = 0;
	int i = 0;
	
	CharToShort conv;
	
	// for refString.sgetc()
	refString.reset();
	
	while ((c = refString.sgetc()) != EOF)
	{
		// notice I'm not checking for failure here
		// I'm assuming the hex digits come in groups of 2
		// If they don't, we will crash here.
		d = refString.sgetc();
		
		ca[0] = c;
		ca[1] = d;
		ca[2] = 0;
		
#ifdef _WIN32
		sscanf_s(ca, "%2x", &shTemp);
#else
		sscanf(ca, "%2x", &shTemp); // todo security replace this with something more secure. NOTE: pretty safe though since I'm setting up up myself.
#endif
		
		// at this point, the string has been converted into the unsigned int.
		
		// Even though the number is stored in an unsigned int right now,
		// we know that it was originally in byte form and converted from a single
		// byte to a 2-digit hex whenever GetString was called.
		// Therefore, we KNOW that it will fit into a byte now, and since it 
		// is small enough to fit into a byte, we will take that one byte out of
		// the unsigned int and then add that byte to the tempArray.
		// This way we have reconstructed the binary array.
		conv.sh = shTemp;
		tempArray[i] = conv.c[0];
		
		shTemp=0;
		conv.sh = 0;
		
		i++;
	}
	
	Assign((void *)tempArray, i);

	OT_ASSERT_MSG(64 == i, "ID wrong length after calculation.");
}

/*
 
 for (i = 0; i < md_len; i++) OTLog::vError("%02x", md_value[i]);
 OTLog::Error("\n");
 
 */

// This Identifier is stored in binary form.
// But what if you want a pretty hex string version of it?
// Just call this function.
void OTIdentifier::GetString(OTString & theStr) const
{
	theStr.Release();
	
	if (IsEmpty()) {
		return;
	}
	
	OT_ASSERT_MSG(64 == GetSize(), "ID wrong length before calculation.");
	
	unsigned char cByte = 0;
	
	for(long i = 0; i < GetSize(); i++)
	{
		cByte = ((unsigned char *)GetPointer())[i];
		
		int n = cByte;
		
		theStr.Concatenate("%02x", n);
	}
	
	OT_ASSERT_MSG(128 == theStr.GetLength(), "String wrong length after ID calculation.");
}


