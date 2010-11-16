/* ----------------------------------------------------------------------------
 * This file was automatically generated by SWIG (http://www.swig.org).
 * Version 1.3.31
 *
 * Do not make changes to this file unless you know what you are doing--modify
 * the SWIG interface file instead.
 * ----------------------------------------------------------------------------- */


class OTAPIJNI {
  public final static native int OT_API_Init(String jarg1);
  public final static native int OT_API_LoadWallet(String jarg1);
  public final static native int OT_API_ConnectServer(String jarg1, String jarg2, String jarg3, String jarg4, String jarg5);
  public final static native int OT_API_ProcessSockets();
  public final static native int OT_API_GetNymCount();
  public final static native int OT_API_GetServerCount();
  public final static native int OT_API_GetAssetTypeCount();
  public final static native int OT_API_GetAccountCount();
  public final static native String OT_API_GetNym_ID(int jarg1);
  public final static native String OT_API_GetNym_Name(String jarg1);
  public final static native String OT_API_GetServer_ID(int jarg1);
  public final static native String OT_API_GetServer_Name(String jarg1);
  public final static native String OT_API_GetAssetType_ID(int jarg1);
  public final static native String OT_API_GetAssetType_Name(String jarg1);
  public final static native String OT_API_GetAccountWallet_ID(int jarg1);
  public final static native String OT_API_GetAccountWallet_Name(String jarg1);
  public final static native String OT_API_GetAccountWallet_Balance(String jarg1);
  public final static native String OT_API_GetAccountWallet_Type(String jarg1);
  public final static native String OT_API_GetAccountWallet_AssetTypeID(String jarg1);
  public final static native String OT_API_WriteCheque(String jarg1, String jarg2, String jarg3, String jarg4, String jarg5, String jarg6, String jarg7, String jarg8);
  public final static native String OT_API_LoadUserPubkey(String jarg1);
  public final static native int OT_API_VerifyUserPrivateKey(String jarg1);
  public final static native String OT_API_LoadPurse(String jarg1, String jarg2);
  public final static native String OT_API_LoadMint(String jarg1, String jarg2);
  public final static native String OT_API_LoadAssetContract(String jarg1);
  public final static native String OT_API_LoadAssetAccount(String jarg1, String jarg2, String jarg3);
  public final static native String OT_API_LoadInbox(String jarg1, String jarg2, String jarg3);
  public final static native String OT_API_LoadOutbox(String jarg1, String jarg2, String jarg3);
  public final static native int OT_API_Ledger_GetCount(String jarg1, String jarg2, String jarg3, String jarg4);
  public final static native String OT_API_Ledger_CreateResponse(String jarg1, String jarg2, String jarg3, String jarg4);
  public final static native String OT_API_Ledger_GetTransactionByIndex(String jarg1, String jarg2, String jarg3, String jarg4, int jarg5);
  public final static native String OT_API_Ledger_GetTransactionByID(String jarg1, String jarg2, String jarg3, String jarg4, String jarg5);
  public final static native String OT_API_Ledger_GetTransactionIDByIndex(String jarg1, String jarg2, String jarg3, String jarg4, int jarg5);
  public final static native String OT_API_Ledger_AddTransaction(String jarg1, String jarg2, String jarg3, String jarg4, String jarg5);
  public final static native String OT_API_Transaction_CreateResponse(String jarg1, String jarg2, String jarg3, String jarg4, String jarg5, int jarg6);
  public final static native String OT_API_Transaction_GetType(String jarg1, String jarg2, String jarg3, String jarg4);
  public final static native void OT_API_checkServerID(String jarg1, String jarg2);
  public final static native void OT_API_createUserAccount(String jarg1, String jarg2);
  public final static native void OT_API_checkUser(String jarg1, String jarg2, String jarg3);
  public final static native void OT_API_getRequest(String jarg1, String jarg2);
  public final static native void OT_API_getTransactionNumber(String jarg1, String jarg2);
  public final static native void OT_API_issueAssetType(String jarg1, String jarg2, String jarg3);
  public final static native void OT_API_getContract(String jarg1, String jarg2, String jarg3);
  public final static native void OT_API_getMint(String jarg1, String jarg2, String jarg3);
  public final static native void OT_API_createAssetAccount(String jarg1, String jarg2, String jarg3);
  public final static native void OT_API_getAccount(String jarg1, String jarg2, String jarg3);
  public final static native void OT_API_issueBasket(String jarg1, String jarg2, String jarg3);
  public final static native void OT_API_exchangeBasket(String jarg1, String jarg2, String jarg3, String jarg4);
  public final static native void OT_API_notarizeWithdrawal(String jarg1, String jarg2, String jarg3, String jarg4);
  public final static native void OT_API_notarizeDeposit(String jarg1, String jarg2, String jarg3, String jarg4);
  public final static native void OT_API_notarizeTransfer(String jarg1, String jarg2, String jarg3, String jarg4, String jarg5, String jarg6);
  public final static native void OT_API_getInbox(String jarg1, String jarg2, String jarg3);
  public final static native void OT_API_processInbox(String jarg1, String jarg2, String jarg3, String jarg4);
  public final static native void OT_API_withdrawVoucher(String jarg1, String jarg2, String jarg3, String jarg4, String jarg5, String jarg6);
  public final static native void OT_API_depositCheque(String jarg1, String jarg2, String jarg3, String jarg4);
}
