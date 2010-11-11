# This file was automatically generated by SWIG (http://www.swig.org).
# Version 1.3.31
#
# Don't modify this file, modify the SWIG interface instead.
# This file is compatible with both classic and new-style classes.

import _OTAPI
import new
new_instancemethod = new.instancemethod
try:
    _swig_property = property
except NameError:
    pass # Python < 2.2 doesn't have 'property'.
def _swig_setattr_nondynamic(self,class_type,name,value,static=1):
    if (name == "thisown"): return self.this.own(value)
    if (name == "this"):
        if type(value).__name__ == 'PySwigObject':
            self.__dict__[name] = value
            return
    method = class_type.__swig_setmethods__.get(name,None)
    if method: return method(self,value)
    if (not static) or hasattr(self,name):
        self.__dict__[name] = value
    else:
        raise AttributeError("You cannot add attributes to %s" % self)

def _swig_setattr(self,class_type,name,value):
    return _swig_setattr_nondynamic(self,class_type,name,value,0)

def _swig_getattr(self,class_type,name):
    if (name == "thisown"): return self.this.own()
    method = class_type.__swig_getmethods__.get(name,None)
    if method: return method(self)
    raise AttributeError,name

def _swig_repr(self):
    try: strthis = "proxy of " + self.this.__repr__()
    except: strthis = ""
    return "<%s.%s; %s >" % (self.__class__.__module__, self.__class__.__name__, strthis,)

import types
try:
    _object = types.ObjectType
    _newclass = 1
except AttributeError:
    class _object : pass
    _newclass = 0
del types


OT_API_Init = _OTAPI.OT_API_Init
OT_API_loadWallet = _OTAPI.OT_API_loadWallet
OT_API_connectServer = _OTAPI.OT_API_connectServer
OT_API_processSockets = _OTAPI.OT_API_processSockets
OT_API_checkServerID = _OTAPI.OT_API_checkServerID
OT_API_createUserAccount = _OTAPI.OT_API_createUserAccount
OT_API_checkUser = _OTAPI.OT_API_checkUser
OT_API_getRequest = _OTAPI.OT_API_getRequest
OT_API_issueAssetType = _OTAPI.OT_API_issueAssetType
OT_API_getContract = _OTAPI.OT_API_getContract
OT_API_getMint = _OTAPI.OT_API_getMint
OT_API_createAssetAccount = _OTAPI.OT_API_createAssetAccount
OT_API_getAccount = _OTAPI.OT_API_getAccount
OT_API_issueBasket = _OTAPI.OT_API_issueBasket
OT_API_exchangeBasket = _OTAPI.OT_API_exchangeBasket
OT_API_getTransactionNumber = _OTAPI.OT_API_getTransactionNumber
OT_API_notarizeWithdrawal = _OTAPI.OT_API_notarizeWithdrawal
OT_API_notarizeDeposit = _OTAPI.OT_API_notarizeDeposit
OT_API_notarizeTransfer = _OTAPI.OT_API_notarizeTransfer
OT_API_getInbox = _OTAPI.OT_API_getInbox
OT_API_processInbox = _OTAPI.OT_API_processInbox
OT_API_withdrawVoucher = _OTAPI.OT_API_withdrawVoucher
OT_API_depositCheque = _OTAPI.OT_API_depositCheque
OT_API_getNymCount = _OTAPI.OT_API_getNymCount
OT_API_getServerCount = _OTAPI.OT_API_getServerCount
OT_API_getAssetTypeCount = _OTAPI.OT_API_getAssetTypeCount
OT_API_getAccountCount = _OTAPI.OT_API_getAccountCount
OT_API_getNym = _OTAPI.OT_API_getNym
OT_API_getServer = _OTAPI.OT_API_getServer
OT_API_getAssetType = _OTAPI.OT_API_getAssetType
OT_API_GetAccountWallet = _OTAPI.OT_API_GetAccountWallet

