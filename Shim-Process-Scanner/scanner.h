#include<stdio.h>
#include<Windows.h>
#include"Winternl.h"
#include<stddef.h>
#include<inttypes.h>

/* From Moonsols.com -> msdn */
typedef struct _ACTIVATION_CONTEXT_DATA // 0 elements, 0x0 bytes (sizeof)
{
}ACTIVATION_CONTEXT_DATA, *PACTIVATION_CONTEXT_DATA;

typedef struct _ASSEMBLY_STORAGE_MAP // 0 elements, 0x0 bytes (sizeof)
{
}ASSEMBLY_STORAGE_MAP, *PASSEMBLY_STORAGE_MAP;

typedef struct _FLS_CALLBACK_INFO // 0 elements, 0x0 bytes (sizeof)
{
}FLS_CALLBACK_INFO, *PFLS_CALLBACK_INFO;


//replacing _PEB_LDR_DATA
typedef struct _moonsols_win7_PEB_LDR_DATA                            // 9 elements, 0x58 bytes (sizeof)
{
	/*0x000*/     ULONG32      Length;
	/*0x004*/     UINT8        Initialized;
	/*0x005*/     UINT8        _PADDING0_[0x3];
	/*0x008*/     VOID*        SsHandle;
	/*0x010*/     struct _LIST_ENTRY InLoadOrderModuleList;           // 2 elements, 0x10 bytes (sizeof)
	/*0x020*/     struct _LIST_ENTRY InMemoryOrderModuleList;         // 2 elements, 0x10 bytes (sizeof)
	/*0x030*/     struct _LIST_ENTRY InInitializationOrderModuleList; // 2 elements, 0x10 bytes (sizeof)
	/*0x040*/     VOID*        EntryInProgress;
	/*0x048*/     UINT8        ShutdownInProgress;
	/*0x049*/     UINT8        _PADDING1_[0x7];
	/*0x050*/     VOID*        ShutdownThreadId;
}moonsols_win7_PEB_LDR_DATA, *P_moonsols_win7_PEB_LDR_DATA;

//replacing _LDR_DATA_TABLE_ENTRY
typedef struct   _moonsols_win7_LDR_DATA_TABLE_ENTRY                       // 24 elements, 0xE0 bytes (sizeof)
{
	/*0x000*/     struct _LIST_ENTRY InLoadOrderLinks;                     // 2 elements, 0x10 bytes (sizeof)
	/*0x010*/     struct _LIST_ENTRY InMemoryOrderLinks;                   // 2 elements, 0x10 bytes (sizeof)
	/*0x020*/     struct _LIST_ENTRY InInitializationOrderLinks;           // 2 elements, 0x10 bytes (sizeof)
	/*0x030*/     VOID*        DllBase;
	/*0x038*/     VOID*        EntryPoint;
	/*0x040*/     ULONG32      SizeOfImage;
	/*0x044*/     UINT8        _PADDING0_[0x4];
	/*0x048*/     struct _UNICODE_STRING FullDllName;                      // 3 elements, 0x10 bytes (sizeof)
	/*0x058*/     struct _UNICODE_STRING BaseDllName;                      // 3 elements, 0x10 bytes (sizeof)
	/*0x068*/     ULONG32      Flags;
	/*0x06C*/     UINT16       LoadCount;
	/*0x06E*/     UINT16       TlsIndex;
	union                                                    // 2 elements, 0x10 bytes (sizeof)
	{
		/*0x070*/         struct _LIST_ENTRY HashLinks;                        // 2 elements, 0x10 bytes (sizeof)
		struct                                               // 2 elements, 0x10 bytes (sizeof)
		{
			/*0x070*/             VOID*        SectionPointer;
			/*0x078*/             ULONG32      CheckSum;
			/*0x07C*/             UINT8        _PADDING1_[0x4];
		};
	};
	union                                                    // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x080*/         ULONG32      TimeDateStamp;
		/*0x080*/         VOID*        LoadedImports;
	};
	/*0x088*/     struct _ACTIVATION_CONTEXT* EntryPointActivationContext;
	/*0x090*/     VOID*        PatchInformation;
	/*0x098*/     struct _LIST_ENTRY ForwarderLinks;                       // 2 elements, 0x10 bytes (sizeof)
	/*0x0A8*/     struct _LIST_ENTRY ServiceTagLinks;                      // 2 elements, 0x10 bytes (sizeof)
	/*0x0B8*/     struct _LIST_ENTRY StaticLinks;                          // 2 elements, 0x10 bytes (sizeof)
	/*0x0C8*/     VOID*        ContextInformation;
	/*0x0D0*/     UINT64       OriginalBase;
	/*0x0D8*/     union _LARGE_INTEGER LoadTime;                           // 4 elements, 0x8 bytes (sizeof)
}moonsols_LDR_DATA_TABLE_ENTRY, *P_moonsols_LDR_DATA_TABLE_ENTRY;

typedef struct nirSoft_vista_PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PPEB_LDR_DATA           LoaderData;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID         FastPebLockRoutine;
	PVOID         FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID                  KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID         FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PVOID                  ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PVOID                  *ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;

	ULARGE_INTEGER AppCompatFlags;
	ULARGE_INTEGER AppCompatFlagsUser;
	PVOID pShimData;
	PVOID AppCompatInfo;
	UNICODE_STRING CSDVersion;
	_ACTIVATION_CONTEXT_DATA * ActivationContextData;
	_ASSEMBLY_STORAGE_MAP * ProcessAssemblyStorageMap;
	_ACTIVATION_CONTEXT_DATA * SystemDefaultActivationContextData;
	_ASSEMBLY_STORAGE_MAP * SystemAssemblyStorageMap;
	ULONG MinimumStackCommit;
	_FLS_CALLBACK_INFO * FlsCallback;
	LIST_ENTRY FlsListHead;
	PVOID FlsBitmap;
	ULONG FlsBitmapBits[4];
	ULONG FlsHighIndex;
	PVOID WerRegistrationData;
	PVOID WerShipAssertPtr;

} ns_PEB, *P_ns_PEB;


/* Offsets are correct on this one */
typedef struct moonsols_win7_PEB                                                                               // 91 elements, 0x380 bytes (sizeof)
{
	/*0x000*/     UINT8        InheritedAddressSpace;
	/*0x001*/     UINT8        ReadImageFileExecOptions;
	/*0x002*/     UINT8        BeingDebugged;
	union                                                                                         // 2 elements, 0x1 bytes (sizeof)
	{
		/*0x003*/         UINT8        BitField;
		struct                                                                                    // 6 elements, 0x1 bytes (sizeof)
		{
			/*0x003*/             UINT8        ImageUsesLargePages : 1;                                                 // 0 BitPosition
			/*0x003*/             UINT8        IsProtectedProcess : 1;                                                  // 1 BitPosition
			/*0x003*/             UINT8        IsLegacyProcess : 1;                                                     // 2 BitPosition
			/*0x003*/             UINT8        IsImageDynamicallyRelocated : 1;                                         // 3 BitPosition
			/*0x003*/             UINT8        SkipPatchingUser32Forwarders : 1;                                        // 4 BitPosition
			/*0x003*/             UINT8        SpareBits : 3;                                                           // 5 BitPosition
		};
	};
	/*0x008*/     VOID*        Mutant;
	/*0x010*/     VOID*        ImageBaseAddress;
	/*0x018*/     struct _moonsols_win7_PEB_LDR_DATA* Ldr;
	/*0x020*/     struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
	/*0x028*/     VOID*        SubSystemData;
	/*0x030*/     VOID*        ProcessHeap;
	/*0x038*/     struct _RTL_CRITICAL_SECTION* FastPebLock;
	/*0x040*/     VOID*        AtlThunkSListPtr;
	/*0x048*/     VOID*        IFEOKey;
	union                                                                                         // 2 elements, 0x4 bytes (sizeof)
	{
		/*0x050*/         ULONG32      CrossProcessFlags;
		struct                                                                                    // 6 elements, 0x4 bytes (sizeof)
		{
			/*0x050*/             ULONG32      ProcessInJob : 1;                                                        // 0 BitPosition
			/*0x050*/             ULONG32      ProcessInitializing : 1;                                                 // 1 BitPosition
			/*0x050*/             ULONG32      ProcessUsingVEH : 1;                                                     // 2 BitPosition
			/*0x050*/             ULONG32      ProcessUsingVCH : 1;                                                     // 3 BitPosition
			/*0x050*/             ULONG32      ProcessUsingFTH : 1;                                                     // 4 BitPosition
			/*0x050*/             ULONG32      ReservedBits0 : 27;                                                      // 5 BitPosition
		};
	};
	union                                                                                         // 2 elements, 0x8 bytes (sizeof)
	{
		/*0x058*/         VOID*        KernelCallbackTable;
		/*0x058*/         VOID*        UserSharedInfoPtr;
	};
	/*0x060*/     ULONG32      SystemReserved[1];
	/*0x064*/     ULONG32      AtlThunkSListPtr32;
	/*0x068*/     VOID*        ApiSetMap;
	/*0x070*/     ULONG32      TlsExpansionCounter;
	/*0x074*/     UINT8        _PADDING0_[0x4];
	/*0x078*/     VOID*        TlsBitmap;
	/*0x080*/     ULONG32      TlsBitmapBits[2];
	/*0x088*/     VOID*        ReadOnlySharedMemoryBase;
	/*0x090*/     VOID*        HotpatchInformation;
	/*0x098*/     VOID**       ReadOnlyStaticServerData;
	/*0x0A0*/     VOID*        AnsiCodePageData;
	/*0x0A8*/     VOID*        OemCodePageData;
	/*0x0B0*/     VOID*        UnicodeCaseTableData;
	/*0x0B8*/     ULONG32      NumberOfProcessors;
	/*0x0BC*/     ULONG32      NtGlobalFlag;
	/*0x0C0*/     union _LARGE_INTEGER CriticalSectionTimeout;                                                  // 4 elements, 0x8 bytes (sizeof)
	/*0x0C8*/     UINT64       HeapSegmentReserve;
	/*0x0D0*/     UINT64       HeapSegmentCommit;
	/*0x0D8*/     UINT64       HeapDeCommitTotalFreeThreshold;
	/*0x0E0*/     UINT64       HeapDeCommitFreeBlockThreshold;
	/*0x0E8*/     ULONG32      NumberOfHeaps;
	/*0x0EC*/     ULONG32      MaximumNumberOfHeaps;
	/*0x0F0*/     VOID**       ProcessHeaps;
	/*0x0F8*/     VOID*        GdiSharedHandleTable;
	/*0x100*/     VOID*        ProcessStarterHelper;
	/*0x108*/     ULONG32      GdiDCAttributeList;
	/*0x10C*/     UINT8        _PADDING1_[0x4];
	/*0x110*/     struct _RTL_CRITICAL_SECTION* LoaderLock;
	/*0x118*/     ULONG32      OSMajorVersion;
	/*0x11C*/     ULONG32      OSMinorVersion;
	/*0x120*/     UINT16       OSBuildNumber;
	/*0x122*/     UINT16       OSCSDVersion;
	/*0x124*/     ULONG32      OSPlatformId;
	/*0x128*/     ULONG32      ImageSubsystem;
	/*0x12C*/     ULONG32      ImageSubsystemMajorVersion;
	/*0x130*/     ULONG32      ImageSubsystemMinorVersion;
	/*0x134*/     UINT8        _PADDING2_[0x4];
	/*0x138*/     UINT64       ActiveProcessAffinityMask;
	/*0x140*/     ULONG32      GdiHandleBuffer[60];
	/*0x230*/     PVOID PostProcessInitRoutine;
	/*0x238*/     VOID*        TlsExpansionBitmap;
	/*0x240*/     ULONG32      TlsExpansionBitmapBits[32];
	/*0x2C0*/     ULONG32      SessionId;
	/*0x2C4*/     UINT8        _PADDING3_[0x4];
	/*0x2C8*/     union _ULARGE_INTEGER AppCompatFlags;                                                         // 4 elements, 0x8 bytes (sizeof)
	/*0x2D0*/     union _ULARGE_INTEGER AppCompatFlagsUser;                                                     // 4 elements, 0x8 bytes (sizeof)
	/*0x2D8*/     VOID*        pShimData;
	/*0x2E0*/     VOID*        AppCompatInfo;
	/*0x2E8*/     struct _UNICODE_STRING CSDVersion;                                                            // 3 elements, 0x10 bytes (sizeof)
	/*0x2F8*/     struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;
	/*0x300*/     struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;
	/*0x308*/     struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;
	/*0x310*/     struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;
	/*0x318*/     UINT64       MinimumStackCommit;
	/*0x320*/     struct _FLS_CALLBACK_INFO* FlsCallback;
	/*0x328*/     struct _LIST_ENTRY FlsListHead;                                                               // 2 elements, 0x10 bytes (sizeof)
	/*0x338*/     VOID*        FlsBitmap;
	/*0x340*/     ULONG32      FlsBitmapBits[4];
	/*0x350*/     ULONG32      FlsHighIndex;
	/*0x354*/     UINT8        _PADDING4_[0x4];
	/*0x358*/     VOID*        WerRegistrationData;
	/*0x360*/     VOID*        WerShipAssertPtr;
	/*0x368*/     VOID*        pContextData;
	/*0x370*/     VOID*        pImageHeaderHash;
	union                                                                                         // 2 elements, 0x4 bytes (sizeof)
	{
		/*0x378*/         ULONG32      TracingFlags;
		struct                                                                                    // 3 elements, 0x4 bytes (sizeof)
		{
			/*0x378*/             ULONG32      HeapTracingEnabled : 1;                                                  // 0 BitPosition
			/*0x378*/             ULONG32      CritSecTracingEnabled : 1;                                               // 1 BitPosition
			/*0x378*/             ULONG32      SpareTracingBits : 30;                                                   // 2 BitPosition
		};
	};
} moonsols_win7_PEB, *P_moonsols_win7_PEB;