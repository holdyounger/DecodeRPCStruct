#pragma once

#include <windows.h>

#ifndef __RPCDCEP_H__

typedef struct _RPC_VERSION {
    unsigned short MajorVersion;
    unsigned short MinorVersion;
} RPC_VERSION;

typedef struct _RPC_SYNTAX_IDENTIFIER {
    GUID SyntaxGUID;
    RPC_VERSION SyntaxVersion;
} RPC_SYNTAX_IDENTIFIER, __RPC_FAR* PRPC_SYNTAX_IDENTIFIER;

typedef struct _RPC_SERVER_INTERFACE
{
	/* 0x0000 */ unsigned int Length;
	/* 0x0004 */ struct _RPC_SYNTAX_IDENTIFIER InterfaceId;
	/* 0x0018 */ struct _RPC_SYNTAX_IDENTIFIER TransferSyntax;
	/* 0x0030 */ struct RPC_DISPATCH_TABLE* DispatchTable;
	/* 0x0038 */ unsigned int RpcProtseqEndpointCount;
	/* 0x0040 */ struct _RPC_PROTSEQ_ENDPOINT* RpcProtseqEndpoint;
	/* 0x0048 */ void* DefaultManagerEpv;
	/* 0x0050 */ const void* InterpreterInfo;
	/* 0x0058 */ unsigned int Flags;
	/* 0x005c */ long __PADDING__[1];
} RPC_SERVER_INTERFACE, * PRPC_SERVER_INTERFACE; /* size: 0x0060 */
#endif

#ifndef __RPCNDR_H__
/*
 * MIDL Stub Descriptor
 */

typedef struct _MIDL_STUB_DESC
{
    void* RpcInterfaceInformation;

    void* (__RPC_API* pfnAllocate)(size_t);
    void       (__RPC_API* pfnFree)(void*);

    union
    {
        handle_t* pAutoHandle;
        handle_t* pPrimitiveHandle;
        PGENERIC_BINDING_INFO   pGenericBindingInfo;
    } IMPLICIT_HANDLE_INFO;

    const NDR_RUNDOWN* apfnNdrRundownRoutines;
    const GENERIC_BINDING_ROUTINE_PAIR* aGenericBindingRoutinePairs;
    const EXPR_EVAL* apfnExprEval;
    const XMIT_ROUTINE_QUINTUPLE* aXmitQuintuple;

    const unsigned char* pFormatTypes;

    int                                     fCheckBounds;

    /* Ndr library version. */
    unsigned long                           Version;

    MALLOC_FREE_STRUCT* pMallocFreeStruct;

    long                                    MIDLVersion;

    const COMM_FAULT_OFFSETS* CommFaultOffsets;

    // New fields for version 3.0+
    const USER_MARSHAL_ROUTINE_QUADRUPLE* aUserMarshalQuadruple;

    // Notify routines - added for NT5, MIDL 5.0
    const NDR_NOTIFY_ROUTINE* NotifyRoutineTable;

    /*
     * Reserved for future use.
     */

    ULONG_PTR                               mFlags;

    // International support routines - added for 64bit post NT5
    const NDR_CS_ROUTINES* CsRoutineTables;

    void* ProxyServerInfo;
    const NDR_EXPR_DESC* pExprInfo;

    // Fields up to now present in win2000 release.

} MIDL_STUB_DESC;


typedef const MIDL_STUB_DESC* PMIDL_STUB_DESC;


/*
 * Stub thunk used for some interpreted server stubs.
 */
typedef void (__RPC_API* STUB_THUNK)(PMIDL_STUB_MESSAGE);

#ifndef _MANAGED
typedef long (__RPC_API* SERVER_ROUTINE)();
#else
typedef long (__RPC_API* SERVER_ROUTINE)(void);
#endif


/*
 * Server Interpreter's information strucuture.
 */
typedef struct  _MIDL_SERVER_INFO_
{
	PMIDL_STUB_DESC                     pStubDesc;
	const SERVER_ROUTINE* DispatchTable;
	PFORMAT_STRING                      ProcString;
	const unsigned short* FmtStringOffset;
	const STUB_THUNK* ThunkTable;
	PRPC_SYNTAX_IDENTIFIER              pTransferSyntax;
	ULONG_PTR                           nCount;
	PMIDL_SYNTAX_INFO                   pSyntaxInfo;
} MIDL_SERVER_INFO, * PMIDL_SERVER_INFO;

#endif

typedef struct
{
    unsigned char   FullPtrUsed : 1;
    unsigned char   RpcSsAllocUsed : 1;
    unsigned char   ObjectProc : 1;
    unsigned char   HasRpcFlags : 1;
    unsigned char   IgnoreObjectException : 1;
    unsigned char   HasCommOrFault : 1;
    unsigned char   UseNewInitRoutines : 1;
    unsigned char   Unused : 1;
} INTERPRETER_FLAGS, * PINTERPRETER_FLAGS;

typedef struct {
    unsigned char HasNewCorrDesc : 1;
    unsigned char ClientCorrCheck : 1;
    unsigned char ServerCorrCheck : 1;
    unsigned char HasNotify : 1;
    unsigned char HasNotify2 : 1;
    unsigned char Unused : 3;
} INTERPRETER_OPT_FLAGS2, * PINTERPRETER_OPT_FLAGS2;

typedef struct {
    unsigned char Size;
    INTERPRETER_OPT_FLAGS2 Flags2;
    unsigned short ClientCorrHint;
    unsigned short ServerCorrHint;
    unsigned short NotifyIndex;
} NDR_PROC_HEADER_EXTS, * PNDR_PROC_HEADER_EXTS; 

typedef struct
{
    unsigned char   ServerMustSize : 1;
    unsigned char   ClientMustSize : 1;
    unsigned char   HasReturn : 1;
    unsigned char   HasPipes : 1;
    unsigned char   Unused : 1;
    unsigned char   HasAsyncUuid : 1;
    unsigned char   HasExtensions : 1;
    unsigned char   HasAsyncHandle : 1;
} INTERPRETER_OPT_FLAGS, * PINTERPRETER_OPT_FLAGS;

typedef struct _NDR_PROC_DESC
{
    unsigned short              ClientBufferSize;    // The Oi2 header
    unsigned short              ServerBufferSize;    //
    INTERPRETER_OPT_FLAGS       Oi2Flags;            //
    unsigned char               NumberParams;        //
    NDR_PROC_HEADER_EXTS        NdrExts;
} NDR_PROC_DESC, * PNDR_PROC_DESC;

typedef struct _NDR_PROC_INFO
{
    INTERPRETER_FLAGS           InterpreterFlags;
    NDR_PROC_DESC* pProcDesc;
} NDR_PROC_INFO, * PNDR_PROC_INFO;

typedef struct _NDR_ALLOCA_CONTEXT
{
    /* 0x0000 */ unsigned char* pBlockPointer;
    /* 0x0004 */ struct _LIST_ENTRY MemoryList;
    /* 0x000c */ unsigned long BytesRemaining;
    /* 0x0010 */ unsigned char PreAllocatedBlock[512];
} NDR_ALLOCA_CONTEXT, * PNDR_ALLOCA_CONTEXT; /* size: 0x0210 */

typedef struct _NDR_PROC_CONTEXT
{
    /* 0x0000 */ enum SYNTAX_TYPE CurrentSyntaxType;
    union
    {
        /* 0x0004 */ struct _NDR_PROC_INFO NdrInfo;
        /* 0x0004 */ struct _NDR64_PROC_FORMAT* Ndr64Header;
    }; /* size: 0x0008 */
    /* 0x000c */ const unsigned char* pProcFormat;
    /* 0x0010 */ unsigned long NumberParams;
    /* 0x0014 */ void* Params;
    /* 0x0018 */ unsigned char* StartofStack;
    /* 0x001c */ unsigned char HandleType;
    /* 0x001d */ unsigned char CorrIncrement;
    /* 0x0020 */ void* SavedGenericHandle;
    /* 0x0024 */ const unsigned char* pHandleFormatSave;
    /* 0x0028 */ const unsigned char* DceTypeFormatString;
    struct /* bitfield */
    {
        /* 0x002c */ unsigned long IsAsync : 1; /* bit position: 0 */
        /* 0x002c */ unsigned long IsObject : 1; /* bit position: 1 */
        /* 0x002c */ unsigned long HasPipe : 1; /* bit position: 2 */
        /* 0x002c */ unsigned long HasComplexReturn : 1; /* bit position: 3 */
        /* 0x002c */ unsigned long NeedsResend : 1; /* bit position: 4 */
        /* 0x002c */ unsigned long UseLocator : 1; /* bit position: 5 */
        /* 0x002c */ unsigned long Reserved7 : 1; /* bit position: 6 */
        /* 0x002c */ unsigned long Reserved8 : 1; /* bit position: 7 */
        /* 0x002c */ unsigned long Reservedleft : 8; /* bit position: 8 */
    }; /* bitfield */
    /* 0x0030 */ unsigned long FloatDoubleMask;
    /* 0x0034 */ unsigned long ResendCount;
    /* 0x0038 */ unsigned long RpcFlags;
    /* 0x003c */ unsigned long ExceptionFlag;
    /* 0x0040 */ unsigned long StackSize;
    /* 0x0044 */ struct _MIDL_SYNTAX_INFO* pSyntaxInfo;
    /* 0x0048 */ void* pfnValidate /* function */;
    /* 0x004c */ void* ValidateCookie;
    /* 0x0050 */ void* pfnInit /* function */;
    /* 0x0054 */ void* pfnSizing /* function */;
    /* 0x0058 */ void* pfnMarshal /* function */;
    /* 0x005c */ void* pfnUnMarshal /* function */;
    /* 0x0060 */ void* pfnExceptionHandling /* function */;
    /* 0x0064 */ void* pfnClientFinally /* function */;
    /* 0x0068 */ void* pfnGetBuffer /* function */;
    /* 0x006c */ void* pfnSendReceive /* function */;
    /* 0x0070 */ struct _NDR_PIPE_DESC* pPipeDesc;
    /* 0x0074 */ class NDR_POINTER_QUEUE_ELEMENT* pQueueFreeList;
    /* 0x0078 */ class NDR_MINICOMPUTE_QUEUE* pMiniComputeQueue;
    /* 0x007c */ class NDR_MINICOMPUTE_QUEUE_ELEMENT* pConfQueueFreeList;
    /* 0x0080 */ const unsigned char* pFormatSupplement;
    /* 0x0084 */ struct _GUID CurrentActivityID;
    /* 0x0094 */ struct _NDR_ALLOCA_CONTEXT AllocateContext;
} NDR_PROC_CONTEXT, * PNDR_PROC_CONTEXT; /* size: 0x02a4 */

typedef unsigned long   ulong;
typedef unsigned char uchar;
typedef unsigned short ushort;

#define FC_AUTO_HANDLE  0x33
#define FC_BIND_PRIMITIVE 0x32
#define PTR_WIRE_SIZE (4)