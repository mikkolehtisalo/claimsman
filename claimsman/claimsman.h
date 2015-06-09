
#ifndef __CLAIMSMAN_H__
#define __CLAIMSMAN_H__


#define CLAIMSMAN_MESSAGE_FILENAME_SIZE   512
#define CLAIMSMAN_MESSAGE_SID_SIZE        256
#define CLAIMSMAN_MESSAGE_TIMESTAMP_SIZE  128
#define DIFF_TO_UNIX_EPOCH 116444736000000000LL

typedef struct _CLAIMSMAN_MESSAGE {
	// File name
	WCHAR FileName[CLAIMSMAN_MESSAGE_FILENAME_SIZE];

	// SID
	WCHAR Sid[CLAIMSMAN_MESSAGE_SID_SIZE];

	// TimeStamp as ISO-8601
	WCHAR TimeStamp[CLAIMSMAN_MESSAGE_TIMESTAMP_SIZE];

	// Unix timestamp + 3 decimals for milliseconds
	__int64 UnixTimeStamp;

	// Access booleans
	BOOLEAN ReadAccess;
	BOOLEAN WriteAccess;
	BOOLEAN DeleteAccess;

	// Size of the file
	__int64 size;

	// Unix timestamp + 3 decimals for milliseconds
	__int64 lastModified;

} CLAIMSMAN_MESSAGE;

typedef struct _CLAIMSMAN_DATA {

	//
	//  The object that identifies this driver.
	//

	PDRIVER_OBJECT DriverObject;

	//
	//  The filter that results from a call to
	//  FltRegisterFilter.
	//

	PFLT_FILTER Filter;

	//
	//  Server port: user mode connects to this port
	//

	PFLT_PORT ServerPort;

	//
	//  Client connection port: only one connection is allowed at a time.,
	//

	PFLT_PORT ClientPort;

	//
	//  File name extensions files we are interested in monitoring
	//

	PUNICODE_STRING MonitoredExtensions;
	ULONG MonitoredExtensionCount;

	//
	// User names that are ignored from events
	//

	PUNICODE_STRING IgnoredUsers;
	ULONG IgnoredUserCount;

} CLAIMSMAN_DATA;

const PWSTR ClaimsmanPortName = L"\\ClaimsmanPort";

#define CLAIMSMAN_STRING_TAG    'Sncs'
#define CLAIMSMAN_REG_TAG    'Sb'


/*************************************************************************
Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
_In_ PDRIVER_OBJECT DriverObject,
_In_ PUNICODE_STRING RegistryPath
);

void
InitializeMessage(
_Inout_ CLAIMSMAN_MESSAGE *message,
_In_ PUNICODE_STRING sid,
_In_ PUNICODE_STRING name,
_In_ BOOLEAN ReadAccess,
_In_ BOOLEAN WriteAccess,
_In_ BOOLEAN DeleteAccess,
_In_ LONGLONG size,
_In_ LONGLONG modified
);

NTSTATUS
claimsmanInstanceSetup(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
_In_ DEVICE_TYPE VolumeDeviceType,
_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
claimsmanInstanceTeardownStart(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
claimsmanInstanceTeardownComplete(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
claimsmanUnload(
_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
claimsmanInstanceQueryTeardown(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
claimsmanPreOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

VOID
claimsmanOperationStatusCallback(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
_In_ NTSTATUS OperationStatus,
_In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
claimsmanPostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
claimsmanPreOperationNoPostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
);

BOOLEAN
claimsmanDoRequestOperationStatus(
_In_ PFLT_CALLBACK_DATA Data
);

NTSTATUS
ClaimsmanMessage(
_In_ PVOID ConnectionCookie,
_In_reads_bytes_opt_(InputBufferSize) PVOID InputBuffer,
_In_ ULONG InputBufferSize,
_Out_writes_bytes_to_opt_(OutputBufferSize, *ReturnOutputBufferLength) PVOID OutputBuffer,
_In_ ULONG OutputBufferSize,
_Out_ PULONG ReturnOutputBufferLength
);

NTSTATUS
ClaimsmanConnect(
_In_ PFLT_PORT ClientPort,
_In_ PVOID ServerPortCookie,
_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
_In_ ULONG SizeOfContext,
_Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
);

VOID
ClaimsmanDisconnect(
_In_opt_ PVOID ConnectionCookie
);

NTSTATUS
InitializeMonitoredExtensions(
_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
InitializeIgnoredUsers(
_In_ PUNICODE_STRING RegistryPath
);

VOID
ClaimsmanFreeExtensions(
);

VOID
ClaimsmanFreeIgnoredUsers(
);

NTSTATUS
ClaimsmanAllocateUnicodeString(
_Inout_ PUNICODE_STRING String
);

VOID
ClaimsmanFreeUnicodeString(
_Inout_ PUNICODE_STRING String
);

BOOLEAN
ClaimsmanCheckExtension(
_In_ PUNICODE_STRING Extension
);

BOOLEAN
ClaimsmanCheckUserIgnore(
_In_ PUNICODE_STRING Extension
);



#endif //  __CLAIMSMAN_H__
