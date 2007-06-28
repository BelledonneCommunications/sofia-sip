#include <stdio.h>
#include <unistd.h>
#include "in_sock.h" 
#include "es_sock.h"
#include "e32base.h"
#include "s32mem.h"
#include "s32strm.h"
#include <commdbconnpref.h>

#include <sofia-sip/su_config.h>
#include <sofia-sip/su.h>


su_sockaddr_t sa_global[1];

extern "C" int su_get_local_ip_addr(su_sockaddr_t *su)
{
	su->su_sin.sin_addr.s_addr = sa_global->su_sin.sin_addr.s_addr;
	su->su_family = sa_global->su_family;
	su->su_len = sa_global->su_len;
	
	return 0;
}

#if 0
// Finds out local IP address of the device
//
extern "C" int su_get_local_ip_address_l(unsigned *ifindex, su_sockaddr_t *su)
{
	TCommDbConnPref iPref;
	RSocketServ aSocketServ;
	RSocket sock;
	
	// Get the IAP id of the underlying interface of this RConnection

	iPref.SetDirection(ECommDbConnectionDirectionOutgoing);
	iPref.SetDialogPreference(ECommDbDialogPrefPrompt);
	//iPref.SetIapId(iapId);
	iPref.SetBearerSet(KCommDbBearerUnknown/*PSD*/);

	aSocketServ = RSocketServ();
	aSocketServ.Connect();
	RConnection aConnection = RConnection();
	aConnection.Open(aSocketServ);
	aConnection.Start(iPref);
	
	*ifindex = iPref.IapId();
	TUint32 iapId = *ifindex;
	
	User::LeaveIfError(sock.Open(aSocketServ, KAfInet, KSockStream, KProtocolInetTcp));
	
	User::LeaveIfError(aConnection.GetIntSetting(_L("IAP\\Id"), iapId));
	
	// Get IP information from the socket
	TSoInetInterfaceInfo ifinfo;
	TPckg<TSoInetInterfaceInfo> ifinfopkg(ifinfo);
	
	TSoInetIfQuery ifquery;
	TPckg<TSoInetIfQuery> ifquerypkg(ifquery);
	
	// To find out which interfaces are using our current IAP, we must 
	// enumerate and go through all of them and make a query by name
	// for each.
	User::LeaveIfError(sock.SetOpt(KSoInetEnumInterfaces, KSolInetIfCtrl));
	while(sock.GetOpt(KSoInetNextInterface, KSolInetIfCtrl, ifinfopkg) == KErrNone)
	{
		ifquery.iName = ifinfo.iName;
		TInt err = sock.GetOpt(KSoInetIfQueryByName, KSolInetIfQuery, ifquerypkg);

		if(err == KErrNone && ifquery.iZone[1] == iapId) // IAP ID is index 1 of iZone
		{
			// We have found an interface using the IAP we are interested in.
			if(ifinfo.iAddress.Address() > 0)
			{
				// found a IPv4 address
	  		//*ipv4 = ifinfo.iAddress.Address();
	  		su->su_sin.sin_addr.s_addr = htonl(ifinfo.iAddress.Address());
	  		su->su_family = 2048;
	  		su->su_len = 28;
	  		
			sock.Close();
			return 0; // stop & return KErrNone
		  }
		}
		else if(err != KErrNone)
		  break;
  }
			
	sock.Close();
	return -1; // return with KErrNotFound
}
#endif

// Set up the access point for the stack
//
extern "C" void *su_localinfo_ap_set(su_sockaddr_t *su, int *ifindex)
{
	TCommDbConnPref iPref;
	RSocketServ aSocketServ;
	RSocket sock;
	
	// Get the IAP id of the underlying interface of this RConnection
	TUint32 iapId;

	iPref.SetDirection(ECommDbConnectionDirectionOutgoing);
	iPref.SetDialogPreference(ECommDbDialogPrefPrompt);
	//iPref.SetIapId(iapId);
	iPref.SetBearerSet(KCommDbBearerUnknown/*PSD*/);

	aSocketServ = RSocketServ();
	aSocketServ.Connect();
	RConnection *aConnection = new RConnection();
	aConnection->Open(aSocketServ);
	aConnection->Start(iPref);
	
	User::LeaveIfError(sock.Open(aSocketServ, KAfInet, KSockStream, KProtocolInetTcp));
	
	User::LeaveIfError(aConnection->GetIntSetting(_L("IAP\\Id"), iapId));
	
	// Get IP information from the socket
	TSoInetInterfaceInfo ifinfo;
	TPckg<TSoInetInterfaceInfo> ifinfopkg(ifinfo);
	
	TSoInetIfQuery ifquery;
	TPckg<TSoInetIfQuery> ifquerypkg(ifquery);
	
	// To find out which interfaces are using our current IAP, we must 
	// enumerate and go through all of them and make a query by name
	// for each.
	User::LeaveIfError(sock.SetOpt(KSoInetEnumInterfaces, KSolInetIfCtrl));
	while(sock.GetOpt(KSoInetNextInterface, KSolInetIfCtrl, ifinfopkg) == KErrNone)
	{
		ifquery.iName = ifinfo.iName;
		TInt err = sock.GetOpt(KSoInetIfQueryByName, KSolInetIfQuery, ifquerypkg);

		if(err == KErrNone && ifquery.iZone[1] == iapId) // IAP ID is index 1 of iZone
		{
			// We have found an interface using the IAP we are interested in.
			if(ifinfo.iAddress.Address() > 0)
			{
				// found a IPv4 address
	  		//*ipv4 = ifinfo.iAddress.Address();
	  		su->su_sin.sin_addr.s_addr = htonl(ifinfo.iAddress.Address());
	  		sa_global->su_sin.sin_addr.s_addr = su->su_sin.sin_addr.s_addr;
	  		sa_global->su_family = su->su_family = AF_INET;
	  		sa_global->su_len = su->su_len = 28;
			*ifindex = iapId;
				//sock.Close();
				//return 0; // stop & return KErrNone
				return (void *) aConnection;
		  }
		}
		else if(err != KErrNone)
		  break;
  }
			
	sock.Close();
	return NULL;//-1; // return with KErrNotFound
}

extern "C" int su_localinfo_ap_deinit(void *aconn)
{
	RConnection *aConnection = (RConnection *) aconn;
	aConnection->Stop();
 	aConnection->Close();
 	delete aConnection;
 	return 0;
}
