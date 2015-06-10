/*++

Module Name:

claimsman.c

Abstract:

This is the main module of the claimsman miniFilter driver.

Environment:

Kernel mode

--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "claimsman.h"
#include <Ntstrsafe.h>
#include <string.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")
#pragma inline_depth(0)

ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 1;

#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

//
//  The default extension to monitor if not configured in the registry
//

UNICODE_STRING MonitoredExtensionDefault = RTL_CONSTANT_STRING(L"docx");

//
//  The default ignored user
//
UNICODE_STRING IgnoredUserDefault = RTL_CONSTANT_STRING(L"S-1-5-18");

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(INIT, InitializeMonitoredExtensions)    
#pragma alloc_text(INIT, InitializeIgnoredUsers)
#pragma alloc_text(PAGE, claimsmanUnload)
#pragma alloc_text(PAGE, claimsmanInstanceQueryTeardown)
#pragma alloc_text(PAGE, claimsmanInstanceSetup)
#pragma alloc_text(PAGE, ClaimsmanConnect)
#pragma alloc_text(PAGE, ClaimsmanDisconnect)
#pragma alloc_text(PAGE, claimsmanInstanceTeardownStart)
#pragma alloc_text(PAGE, claimsmanInstanceTeardownComplete)
#pragma alloc_text(PAGE, ClaimsmanFreeExtensions)    
#pragma alloc_text(PAGE, ClaimsmanFreeIgnoredUsers)   
#pragma alloc_text(PAGE, ClaimsmanAllocateUnicodeString)
#pragma alloc_text(PAGE, ClaimsmanFreeUnicodeString)
#pragma alloc_text(PAGE, ClaimsmanCheckExtension)
#pragma alloc_text(PAGE, ClaimsmanCheckUserIgnore)
#pragma alloc_text(PAGE, InitializeMessage)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	/*
	The I/O Manager sends the IRP_MJ_CREATE request when a new file or directory is being created, or when an existing file, device, directory, or volume is being opened.
	*/
	{ IRP_MJ_CREATE,
	0,
	NULL,
	claimsmanPostOperation },

	{ IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks

	claimsmanUnload,                           //  MiniFilterUnload

	claimsmanInstanceSetup,                    //  InstanceSetup
	claimsmanInstanceQueryTeardown,            //  InstanceQueryTeardown
	claimsmanInstanceTeardownStart,            //  InstanceTeardownStart
	claimsmanInstanceTeardownComplete,         //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};

CLAIMSMAN_DATA ClaimsmanData;

NTSTATUS
claimsmanInstanceSetup(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
_In_ DEVICE_TYPE VolumeDeviceType,
_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

This routine is called whenever a new instance is created on a volume. This
gives us a chance to decide if we need to attach to this volume or not.

If this routine is not defined in the registration structure, automatic
instances are always created.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Flags describing the reason for this attach request.

Return Value:

STATUS_SUCCESS - attach
STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("claimsman!claimsmanInstanceSetup: Entered\n"));

	return STATUS_SUCCESS;
}


NTSTATUS
claimsmanInstanceQueryTeardown(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

This is called when an instance is being manually deleted by a
call to FltDetachVolume or FilterDetach thereby giving us a
chance to fail that detach request.

If this routine is not defined in the registration structure, explicit
detach requests via FltDetachVolume or FilterDetach will always be
failed.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Indicating where this detach request came from.

Return Value:

Returns the status of this operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("claimsman!claimsmanInstanceQueryTeardown: Entered\n"));

	return STATUS_SUCCESS;
}


VOID
claimsmanInstanceTeardownStart(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

This routine is called at the start of instance teardown.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Reason why this instance is being deleted.

Return Value:

None.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("claimsman!claimsmanInstanceTeardownStart: Entered\n"));
}


VOID
claimsmanInstanceTeardownComplete(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

This routine is called at the end of instance teardown.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Reason why this instance is being deleted.

Return Value:

None.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("claimsman!claimsmanInstanceTeardownComplete: Entered\n"));
}


/*************************************************************************
	MiniFilter initialization and unload routines.
	*************************************************************************/

NTSTATUS
DriverEntry(
_In_ PDRIVER_OBJECT DriverObject,
_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Description:

This is the initialization routine for this miniFilter driver.  This
registers with FltMgr and initializes all global data structures.

Arguments:

DriverObject - Pointer to driver object created by the system to
represent this driver.

RegistryPath - Unicode string identifying where the parameters for this
driver are located in the registry.

Return Value:

Routine can return non success error codes.

--*/
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES oa;
	PSECURITY_DESCRIPTOR sd;
	UNICODE_STRING uniString;

	//UNREFERENCED_PARAMETER(RegistryPath);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("claimsman!DriverEntry: Entered\n"));

	//
	//  Default to NonPagedPoolNx for non paged pool allocations where supported.
	//

	ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

	//
	// Obtain the extensions to monitor from the registry
	//

	status = InitializeMonitoredExtensions(RegistryPath);

	if (!NT_SUCCESS(status)) {

		status = STATUS_SUCCESS;

		ClaimsmanData.MonitoredExtensions = &MonitoredExtensionDefault;
		ClaimsmanData.MonitoredExtensionCount = 1;
	}

	//
	// Obtain the ignored users from the registry
	//

	status = InitializeIgnoredUsers(RegistryPath);

	if (!NT_SUCCESS(status)) {

		status = STATUS_SUCCESS;

		ClaimsmanData.IgnoredUsers = &MonitoredExtensionDefault;
		ClaimsmanData.IgnoredUserCount = 1;
	}


	//
	//  Register with FltMgr to tell it our callback routines
	//

	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&ClaimsmanData.Filter);

	if (!NT_SUCCESS(status)) {
		return status;
	}

	//
	// Initialize communication port
	//

	RtlInitUnicodeString(&uniString, ClaimsmanPortName);

	//  Only ADMINs & SYSTEM can access the port

	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);

	if (NT_SUCCESS(status)) {
		InitializeObjectAttributes(&oa,
			&uniString,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL,
			sd);


		status = FltCreateCommunicationPort(ClaimsmanData.Filter,
			&ClaimsmanData.ServerPort,
			&oa,
			NULL,
			ClaimsmanConnect,
			ClaimsmanDisconnect,
			NULL,
			1);

		// Not needed anymore 
		FltFreeSecurityDescriptor(sd);

		if (!NT_SUCCESS(status)) {
			PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
				("claimsman!DriverEntry: Unable to create communication port: %d\n", status));
		}
		else {
			//
			//  Start filtering I/O.
			//

			status = FltStartFiltering(ClaimsmanData.Filter);

			if (!NT_SUCCESS(status)) {
				FltUnregisterFilter(ClaimsmanData.Filter);
				FltCloseCommunicationPort(ClaimsmanData.ServerPort);
			}
		}
	}

	return status;
}

NTSTATUS
claimsmanUnload(
_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

This is the unload routine for this miniFilter driver. This is called
when the minifilter is about to be unloaded. We can fail this unload
request if this is not a mandatory unload indicated by the Flags
parameter.

Arguments:

Flags - Indicating if this is a mandatory unload.

Return Value:

Returns STATUS_SUCCESS.

--*/
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("claimsman!claimsmanUnload: Entered\n"));

	FltCloseCommunicationPort(ClaimsmanData.ServerPort);
	FltUnregisterFilter(ClaimsmanData.Filter);
	ClaimsmanFreeExtensions();
	ClaimsmanFreeIgnoredUsers();

	return STATUS_SUCCESS;
}


/*************************************************************************
	MiniFilter callback routines.
	*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
claimsmanPreOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

This routine is a pre-operation dispatch routine for this miniFilter.

This is non-pageable because it could be called on the paging path

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The context for the completion routine for this
operation.

Return Value:

The return value is the status of the operation.

--*/
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("claimsman!claimsmanPreOperation: Entered\n"));

	//
	//  See if this is an operation we would like the operation status
	//  for.  If so request it.
	//
	//  NOTE: most filters do NOT need to do this.  You only need to make
	//        this call if, for example, you need to know if the oplock was
	//        actually granted.
	//

	if (claimsmanDoRequestOperationStatus(Data)) {

		status = FltRequestOperationStatusCallback(Data,
			claimsmanOperationStatusCallback,
			(PVOID)(++OperationStatusCtx));
		if (!NT_SUCCESS(status)) {

			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
				("claimsman!claimsmanPreOperation: FltRequestOperationStatusCallback Failed, status=%08x\n",
				status));
		}
	}

	// This template code does not do anything with the callbackData, but
	// rather returns FLT_PREOP_SUCCESS_WITH_CALLBACK.
	// This passes the request down to the next miniFilter in the chain.

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
claimsmanOperationStatusCallback(
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
_In_ NTSTATUS OperationStatus,
_In_ PVOID RequesterContext
)
/*++

Routine Description:

This routine is called when the given operation returns from the call
to IoCallDriver.  This is useful for operations where STATUS_PENDING
means the operation was successfully queued.  This is useful for OpLocks
and directory change notification operations.

This callback is called in the context of the originating thread and will
never be called at DPC level.  The file object has been correctly
referenced so that you can access it.  It will be automatically
dereferenced upon return.

This is non-pageable because it could be called on the paging path

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

RequesterContext - The context for the completion routine for this
operation.

OperationStatus -

Return Value:

The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("claimsman!claimsmanOperationStatusCallback: Entered\n"));

	PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
		("claimsman!claimsmanOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
		OperationStatus,
		RequesterContext,
		ParameterSnapshot->MajorFunction,
		ParameterSnapshot->MinorFunction,
		FltGetIrpName(ParameterSnapshot->MajorFunction)));
}

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
)
/*
...
*/
{
	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("claimsman!claimsmanInitializeMessage: Entered\n"));

	// SID
	USHORT len = (sid->Length < ((CLAIMSMAN_MESSAGE_SID_SIZE - 1) * sizeof(WCHAR)))
		? sid->Length
		: (CLAIMSMAN_MESSAGE_SID_SIZE - 1)  * sizeof(WCHAR);

	RtlCopyMemory(message->Sid, sid->Buffer, len);
	message->Sid[(len / sizeof(WCHAR)) + (len % sizeof(WCHAR))] = 0;

	// FileName
	len = (name->Length < ((CLAIMSMAN_MESSAGE_FILENAME_SIZE - 1) * sizeof(WCHAR)))
		? name->Length
		: (CLAIMSMAN_MESSAGE_FILENAME_SIZE - 1)  * sizeof(WCHAR);

	RtlCopyMemory(message->FileName, name->Buffer, len);
	message->FileName[(len / sizeof(WCHAR)) + (len % sizeof(WCHAR))] = 0;

	// Access info
	message->ReadAccess = ReadAccess;
	message->WriteAccess = WriteAccess;
	message->DeleteAccess = DeleteAccess;

	// Size
	message->size = size;
	// Last modified
	TIME_FIELDS  tf;
	message->UnixLastModified = modified;
	LONGLONG tstmp = (modified * 10000) + DIFF_TO_UNIX_EPOCH;
	RtlTimeToTimeFields(&tstmp, &tf);
	RtlStringCchPrintfW((NTSTRSAFE_PWSTR)message->LastModified, CLAIMSMAN_MESSAGE_TIMESTAMP_SIZE - 1, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second, tf.Milliseconds);

	// Event timestamp
	LARGE_INTEGER st;
	KeQuerySystemTime(&st);
	// Store as timestamp (Unix epoch + 3 decimals for milliseconds)
	message->UnixTimeStamp = (st.QuadPart - DIFF_TO_UNIX_EPOCH) / 10000;
	//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
	//	("claimsman!claimsmanInitializeMessage: message->UnixTimeStamp: %I64u\n", message->UnixTimeStamp));
	// And as ISO-8601...
	RtlTimeToTimeFields(&st, &tf);
	RtlStringCchPrintfW((NTSTRSAFE_PWSTR)message->TimeStamp, CLAIMSMAN_MESSAGE_TIMESTAMP_SIZE - 1, L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", tf.Year, tf.Month, tf.Day, tf.Hour, tf.Minute, tf.Second, tf.Milliseconds);
	//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
	//	("claimsman!claimsmanInitializeMessage: message->TimeStamp: %ws\n", message->TimeStamp));
}

BOOLEAN
getSizeModified(
_In_ PFLT_INSTANCE instance,
_In_ PUNICODE_STRING fileName,
_Inout_ LONGLONG *size,
_Inout_ LONGLONG *modified
)
{
	NTSTATUS status;
	HANDLE FileHandle = NULL;
	OBJECT_ATTRIBUTES objectAttributes;
	IO_STATUS_BLOCK ioStatus;
	FILE_BASIC_INFORMATION basicFileInfo;
	FILE_STANDARD_INFORMATION standardFileInfo;

	InitializeObjectAttributes(&objectAttributes,
		fileName,
		OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
		NULL,
		NULL);

	status = FltCreateFile(
		ClaimsmanData.Filter,
		instance,
		&FileHandle,
		FILE_READ_DATA | FILE_READ_ATTRIBUTES,
		&objectAttributes,
		&ioStatus,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0,
		IO_NO_PARAMETER_CHECKING
		);
	if (!NT_SUCCESS(status)) {
		return FALSE;
	}

	status = ZwQueryInformationFile(FileHandle,
		&ioStatus,
		&basicFileInfo,
		sizeof(FILE_BASIC_INFORMATION),
		FileBasicInformation);

	if (!NT_SUCCESS(status)) {
		ZwClose(FileHandle);
		return FALSE;
	}

		status = ZwQueryInformationFile(FileHandle,
		&ioStatus,
		&standardFileInfo,
		sizeof(FILE_STANDARD_INFORMATION),
		FileStandardInformation);
		
	if (!NT_SUCCESS(status)) {
		ZwClose(FileHandle);
		return FALSE;
	}


	*modified = (basicFileInfo.ChangeTime.QuadPart - DIFF_TO_UNIX_EPOCH) / 10000;
	*size = standardFileInfo.EndOfFile.QuadPart;

	ZwClose(FileHandle);
	return TRUE;
}

FLT_POSTOP_CALLBACK_STATUS
claimsmanPostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_In_opt_ PVOID CompletionContext,
_In_ FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

This routine is the post-operation completion routine for this
miniFilter.

This is non-pageable because it may be called at DPC level.

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The completion context set in the pre-operation routine.

Flags - Denotes whether the completion is successful or is being drained.

Return Value:

The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	NTSTATUS status;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	PUNICODE_STRING fileName = NULL;
	PTOKEN_USER pTokenUser = NULL;
	UNICODE_STRING sidString;
	
	LARGE_INTEGER Timeout;
	Timeout.QuadPart = (LONGLONG)1 * 10 * 1000 * 1000;
	
	// If there is no client registered, bail out immediately!
	// If the event is from kernel, bail out immediately!
	// If the event check for existence of file, bail out immediately!
	if (
		(ClaimsmanData.ClientPort == NULL) || 
		(Data->RequestorMode == KernelMode) ||
		(Data->IoStatus.Information == FILE_DOES_NOT_EXIST) ||
		(Data->IoStatus.Information == FILE_EXISTS)
		) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	//  We got a log record, if there is a file object, get its name.

	if (FltObjects->FileObject != NULL) {
		status = FltGetFileNameInformation(Data,
			FLT_FILE_NAME_NORMALIZED |
			FLT_FILE_NAME_QUERY_DEFAULT,
			&nameInfo);
	}
	else {
		//  Can't get a name when there's no file object
		status = STATUS_UNSUCCESSFUL;
	}

	if (NT_SUCCESS(status)) {
		FltParseFileNameInformation(nameInfo);
		fileName = &nameInfo->Name;
		// Produces way too much logging
		//PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		//	("claimsman!claimsmanPostOperation: fileName=%wZ\n", fileName));
	}
	else
	{
		// No point continuing because we obviously did not get a filename anyways
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	//The only IRP you can trust for user information is IRP_MJ_CREATE. Things 
	//like write can be in arbitrary thread context, and even if the call works
	//you can get the wrong SID.

	status = SeQueryInformationToken(SeQuerySubjectContextToken(&(Data->Iopb->Parameters.Create.SecurityContext->AccessState->SubjectSecurityContext)), TokenUser, &pTokenUser);
	if (STATUS_SUCCESS == status && RtlValidSid(pTokenUser->User.Sid))
	{
		// Interesting extension?
		if (ClaimsmanCheckExtension(&nameInfo->Extension)) {
			CLAIMSMAN_MESSAGE msg;

			status = RtlConvertSidToUnicodeString(&sidString, pTokenUser->User.Sid, TRUE);

			if (NT_SUCCESS(status)) {
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					("claimsman!claimsmanPostOperation: SID=%wZ\n", &sidString));
			}
			else {
				// No point continuing because we obviously did not get a valid SID
				FltReleaseFileNameInformation(nameInfo);
				if (pTokenUser != NULL) {
					ExFreePool(pTokenUser);
				}
				return FLT_POSTOP_FINISHED_PROCESSING;
			}

			if (ClaimsmanCheckUserIgnore(&sidString)) {
				// Ignored user! Bail out!
				FltReleaseFileNameInformation(nameInfo);
				if (pTokenUser != NULL) {
					ExFreePool(pTokenUser);
				}
				RtlFreeUnicodeString(&sidString);
				return FLT_POSTOP_FINISHED_PROCESSING;
			}

			LONGLONG size;
			LONGLONG modified;
			getSizeModified(FltObjects->Instance, fileName, &size, &modified);

			InitializeMessage(&msg, &sidString, fileName, FltObjects->FileObject->ReadAccess, FltObjects->FileObject->WriteAccess, FltObjects->FileObject->DeleteAccess, size, modified);

			// Ready, send the message!
			// But only if there's a client connected
			if (ClaimsmanData.ClientPort != NULL) {

				FltSendMessage(ClaimsmanData.Filter,
					&ClaimsmanData.ClientPort,
					&msg,
					sizeof(msg),
					NULL,
					0,
					&Timeout
					);
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					("claimsman!claimsmanPostOperation: sent message=%d\n", status));
			}
			else {
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
					("claimsman!claimsmanPostOperation: no client connected!"));
			}
			RtlFreeUnicodeString(&sidString);
		}
	}

	FltReleaseFileNameInformation(nameInfo);
	if (pTokenUser != NULL) {
		ExFreePool(pTokenUser);
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
claimsmanPreOperationNoPostOperation(
_Inout_ PFLT_CALLBACK_DATA Data,
_In_ PCFLT_RELATED_OBJECTS FltObjects,
_Flt_CompletionContext_Outptr_ PVOID *CompletionContext
)
/*++

Routine Description:

This routine is a pre-operation dispatch routine for this miniFilter.

This is non-pageable because it could be called on the paging path

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The context for the completion routine for this
operation.

Return Value:

The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("claimsman!claimsmanPreOperationNoPostOperation: Entered\n"));

	// This template code does not do anything with the callbackData, but
	// rather returns FLT_PREOP_SUCCESS_NO_CALLBACK.
	// This passes the request down to the next miniFilter in the chain.

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
claimsmanDoRequestOperationStatus(
_In_ PFLT_CALLBACK_DATA Data
)
/*++

Routine Description:

This identifies those operations we want the operation status for.  These
are typically operations that return STATUS_PENDING as a normal completion
status.

Arguments:

Return Value:

TRUE - If we want the operation status
FALSE - If we don't

--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	//
	//  return boolean state based on which operations we are interested in
	//

	return (BOOLEAN)

		//
		//  Check for oplock operations
		//

		(((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
		((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
		(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
		(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
		(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

		||

		//
		//    Check for directy change notification
		//

		((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
		(iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
		);
}

NTSTATUS
ClaimsmanConnect(
_In_ PFLT_PORT ClientPort,
_In_ PVOID ServerPortCookie,
_In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
_In_ ULONG SizeOfContext,
_Flt_ConnectionCookie_Outptr_ PVOID *ConnectionCookie
)
/*++

Routine Description

This is called when user-mode connects to the server
port - to establish a connection

Arguments

ClientPort - This is the pointer to the client port that
will be used to send messages from the filter.
ServerPortCookie - unused
ConnectionContext - unused
SizeofContext   - unused
ConnectionCookie - unused

Return Value

STATUS_SUCCESS - to accept the connection
--*/
{

	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	ClaimsmanData.ClientPort = ClientPort;
	return STATUS_SUCCESS;
}


VOID
ClaimsmanDisconnect(
_In_opt_ PVOID ConnectionCookie
)
/*++

Routine Description

This is called when the connection is torn-down. We use it to close our handle to the connection

Arguments

ConnectionCookie - unused

Return value

None
--*/
{

	PAGED_CODE();

	UNREFERENCED_PARAMETER(ConnectionCookie);

	//
	//  Close our handle
	//

	FltCloseClientPort(ClaimsmanData.Filter, &ClaimsmanData.ClientPort);
	ClaimsmanData.ClientPort = NULL;
}

NTSTATUS
InitializeMonitoredExtensions(
_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Descrition:

This routine sets the the extensions for files to be monitored based
on the registry.

Arguments:

RegistryPath - The path key passed to the driver during DriverEntry.

Return Value:

STATUS_SUCCESS if the function completes successfully.  Otherwise a valid
NTSTATUS code is returned.

--*/
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES attributes;
	HANDLE driverRegKey = NULL;
	UNICODE_STRING valueName;
	PKEY_VALUE_PARTIAL_INFORMATION valueBuffer = NULL;
	ULONG valueLength = 0;
	BOOLEAN closeHandle = FALSE;
	PWCHAR ch;
	SIZE_T length;
	ULONG count;
	PUNICODE_STRING ext;

	PAGED_CODE();

	ClaimsmanData.MonitoredExtensions = NULL;
	ClaimsmanData.MonitoredExtensionCount = 0;

	//
	//  Open the driver registry key.
	//

	InitializeObjectAttributes(&attributes,
		RegistryPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwOpenKey(&driverRegKey,
		KEY_READ,
		&attributes);

	if (!NT_SUCCESS(status)) {

		goto InitializeMonitoredExtensionsCleanup;
	}

	closeHandle = TRUE;

	//
	//   Query the length of the reg value
	//

	RtlInitUnicodeString(&valueName, L"Extensions");

	status = ZwQueryValueKey(driverRegKey,
		&valueName,
		KeyValuePartialInformation,
		NULL,
		0,
		&valueLength);

	if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {

		status = STATUS_INVALID_PARAMETER;
		goto InitializeMonitoredExtensionsCleanup;
	}

	//
	//  Extract the path.
	//

#pragma warning(suppress: 6102)
	valueBuffer = ExAllocatePoolWithTag(NonPagedPool,
		valueLength,
		CLAIMSMAN_REG_TAG);

	if (valueBuffer == NULL) {

		status = STATUS_INSUFFICIENT_RESOURCES;
		goto InitializeMonitoredExtensionsCleanup;
	}

	status = ZwQueryValueKey(driverRegKey,
		&valueName,
		KeyValuePartialInformation,
		valueBuffer,
		valueLength,
		&valueLength);

	if (!NT_SUCCESS(status)) {

		goto InitializeMonitoredExtensionsCleanup;
	}

	ch = (PWCHAR)(valueBuffer->Data);

	count = 0;

	//
	//  Count how many strings are in the multi string
	//

	while (*ch != '\0') {

		ch = ch + wcslen(ch) + 1;
		count++;
	}

	ClaimsmanData.MonitoredExtensions = ExAllocatePoolWithTag(PagedPool,
		count * sizeof(UNICODE_STRING),
		CLAIMSMAN_STRING_TAG);

	if (ClaimsmanData.MonitoredExtensions == NULL) {
		goto InitializeMonitoredExtensionsCleanup;
	}

	ch = (PWCHAR)((PKEY_VALUE_PARTIAL_INFORMATION)valueBuffer->Data);
	ext = ClaimsmanData.MonitoredExtensions;

	while (ClaimsmanData.MonitoredExtensionCount < count) {

		length = wcslen(ch) * sizeof(WCHAR);

		ext->MaximumLength = (USHORT)length;

		status = ClaimsmanAllocateUnicodeString(ext);

		if (!NT_SUCCESS(status)) {
			goto InitializeMonitoredExtensionsCleanup;
		}

		ext->Length = (USHORT)length;

		RtlCopyMemory(ext->Buffer, ch, length);

		ch = ch + length / sizeof(WCHAR) + 1;

		ClaimsmanData.MonitoredExtensionCount++;

		ext++;

	}

InitializeMonitoredExtensionsCleanup:

	//
	//  Note that this function leaks the global buffers.
	//  On failure DriverEntry will clean up the globals
	//  so we don't have to do that here.
	//

	if (valueBuffer != NULL) {

		ExFreePoolWithTag(valueBuffer, CLAIMSMAN_REG_TAG);
		valueBuffer = NULL;
	}

	if (closeHandle) {

		ZwClose(driverRegKey);
	}

	if (!NT_SUCCESS(status)) {

		ClaimsmanFreeExtensions();
	}

	return status;
}

NTSTATUS
InitializeIgnoredUsers(
_In_ PUNICODE_STRING RegistryPath
)
/*++

Routine Descrition:

This routine sets the the ignored users list based on registry.

Arguments:

RegistryPath - The path key passed to the driver during DriverEntry.

Return Value:

STATUS_SUCCESS if the function completes successfully.  Otherwise a valid
NTSTATUS code is returned.

--*/
{
	NTSTATUS status;
	OBJECT_ATTRIBUTES attributes;
	HANDLE driverRegKey = NULL;
	UNICODE_STRING valueName;
	PKEY_VALUE_PARTIAL_INFORMATION valueBuffer = NULL;
	ULONG valueLength = 0;
	BOOLEAN closeHandle = FALSE;
	PWCHAR ch;
	SIZE_T length;
	ULONG count;
	PUNICODE_STRING igu;

	PAGED_CODE();

	ClaimsmanData.IgnoredUsers = NULL;
	ClaimsmanData.IgnoredUserCount = 0;

	//
	//  Open the driver registry key.
	//

	InitializeObjectAttributes(&attributes, RegistryPath,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwOpenKey(&driverRegKey, KEY_READ, &attributes);

	if (!NT_SUCCESS(status)) {

		goto InitializeIgnoredUsersCleanup;
	}

	closeHandle = TRUE;

	//
	//   Query the length of the reg value
	//

	RtlInitUnicodeString(&valueName, L"IgnoredUsers");

	status = ZwQueryValueKey(driverRegKey,
		&valueName,
		KeyValuePartialInformation,
		NULL,
		0,
		&valueLength);

	if (status != STATUS_BUFFER_TOO_SMALL && status != STATUS_BUFFER_OVERFLOW) {

		status = STATUS_INVALID_PARAMETER;
		goto InitializeIgnoredUsersCleanup;
	}

	//
	//  Extract the path.
	//

#pragma warning(suppress: 6102)
	valueBuffer = ExAllocatePoolWithTag(NonPagedPool,
		valueLength,
		CLAIMSMAN_REG_TAG);

	if (valueBuffer == NULL) {

		status = STATUS_INSUFFICIENT_RESOURCES;
		goto InitializeIgnoredUsersCleanup;
	}

	status = ZwQueryValueKey(driverRegKey,
		&valueName,
		KeyValuePartialInformation,
		valueBuffer,
		valueLength,
		&valueLength);

	if (!NT_SUCCESS(status)) {

		goto InitializeIgnoredUsersCleanup;
	}

	ch = (PWCHAR)(valueBuffer->Data);

	count = 0;

	//
	//  Count how many strings are in the multi string
	//

	while (*ch != '\0') {

		ch = ch + wcslen(ch) + 1;
		count++;
	}

	ClaimsmanData.IgnoredUsers = ExAllocatePoolWithTag(PagedPool,
		count * sizeof(UNICODE_STRING),
		CLAIMSMAN_STRING_TAG);

	if (ClaimsmanData.IgnoredUsers == NULL) {
		goto InitializeIgnoredUsersCleanup;
	}

	ch = (PWCHAR)((PKEY_VALUE_PARTIAL_INFORMATION)valueBuffer->Data);
	igu = ClaimsmanData.IgnoredUsers;

	while (ClaimsmanData.IgnoredUserCount < count) {

		length = wcslen(ch) * sizeof(WCHAR);

		igu->MaximumLength = (USHORT)length;

		status = ClaimsmanAllocateUnicodeString(igu);

		if (!NT_SUCCESS(status)) {
			goto InitializeIgnoredUsersCleanup;
		}

		igu->Length = (USHORT)length;

		RtlCopyMemory(igu->Buffer, ch, length);

		ch = ch + length / sizeof(WCHAR) + 1;

		ClaimsmanData.IgnoredUserCount++;

		igu++;

	}

InitializeIgnoredUsersCleanup:

	//
	//  Note that this function leaks the global buffers.
	//  On failure DriverEntry will clean up the globals
	//  so we don't have to do that here.
	//

	if (valueBuffer != NULL) {

		ExFreePoolWithTag(valueBuffer, CLAIMSMAN_REG_TAG);
		valueBuffer = NULL;
	}

	if (closeHandle) {

		ZwClose(driverRegKey);
	}

	if (!NT_SUCCESS(status)) {

		ClaimsmanFreeIgnoredUsers();
	}

	return status;
}


VOID
ClaimsmanFreeExtensions(
)
/*++

Routine Descrition:

This routine cleans up the global buffers on both
teardown and initialization failure.

Arguments:

Return Value:

None.

--*/
{
	PAGED_CODE();

	//
	// Free the strings in the scanned extension array
	//

	while (ClaimsmanData.MonitoredExtensionCount > 0) {

		ClaimsmanData.MonitoredExtensionCount--;

		if (ClaimsmanData.MonitoredExtensions != &MonitoredExtensionDefault) {

			ClaimsmanFreeUnicodeString(ClaimsmanData.MonitoredExtensions + ClaimsmanData.MonitoredExtensionCount);
		}
	}

	if (ClaimsmanData.MonitoredExtensions != &MonitoredExtensionDefault && ClaimsmanData.MonitoredExtensions != NULL) {

		ExFreePoolWithTag(ClaimsmanData.MonitoredExtensions, CLAIMSMAN_STRING_TAG);
	}

	ClaimsmanData.MonitoredExtensions = NULL;

}

VOID
ClaimsmanFreeIgnoredUsers(
)
/*++

Routine Descrition:

This routine cleans up the global buffers on both
teardown and initialization failure.

Arguments:

Return Value:

None.

--*/
{
	PAGED_CODE();

	//
	// Free the strings in the scanned extension array
	//

	while (ClaimsmanData.IgnoredUserCount > 0) {

		ClaimsmanData.IgnoredUserCount--;

		if (ClaimsmanData.IgnoredUsers != &IgnoredUserDefault) {

			ClaimsmanFreeUnicodeString(ClaimsmanData.IgnoredUsers + ClaimsmanData.IgnoredUserCount);
		}
	}

	if (ClaimsmanData.IgnoredUsers != &IgnoredUserDefault && ClaimsmanData.IgnoredUsers != NULL) {

		ExFreePoolWithTag(ClaimsmanData.IgnoredUsers, CLAIMSMAN_STRING_TAG);
	}

	ClaimsmanData.IgnoredUsers = NULL;

}

NTSTATUS
ClaimsmanAllocateUnicodeString(
_Inout_ PUNICODE_STRING String
)
/*++

Routine Description:

This routine allocates a unicode string

Arguments:

String - supplies the size of the string to be allocated in the MaximumLength field
return the unicode string

Return Value:

STATUS_SUCCESS                  - success
STATUS_INSUFFICIENT_RESOURCES   - failure

--*/
{

	PAGED_CODE();

	String->Buffer = ExAllocatePoolWithTag(NonPagedPool,
		String->MaximumLength,
		CLAIMSMAN_STRING_TAG);

	if (String->Buffer == NULL) {

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	String->Length = 0;

	return STATUS_SUCCESS;
}


VOID
ClaimsmanFreeUnicodeString(
_Inout_ PUNICODE_STRING String
)
/*++

Routine Description:

This routine frees a unicode string

Arguments:

String - supplies the string to be freed

Return Value:

None

--*/
{
	PAGED_CODE();

	if (String->Buffer) {

		ExFreePoolWithTag(String->Buffer,
			CLAIMSMAN_STRING_TAG);
		String->Buffer = NULL;
	}

	String->Length = String->MaximumLength = 0;
	String->Buffer = NULL;
}


BOOLEAN
ClaimsmanCheckExtension(
_In_ PUNICODE_STRING Extension
)
/*++

Routine Description:

Checks if this file name extension is something we are interested in

Arguments

Extension - Pointer to the file name extension

Return Value

TRUE - Yes we are interested
FALSE - No
--*/
{
	PAGED_CODE();
	ULONG count;

	if (Extension == NULL || Extension->Length == 0) {

		return FALSE;
	}

	//
	//  Check if it matches any one of our static extension list
	//

	for (count = 0; count < ClaimsmanData.MonitoredExtensionCount; count++) {

		if (RtlCompareUnicodeString(Extension, ClaimsmanData.MonitoredExtensions + count, TRUE) == 0) {

			//
			//  A match. We are interested in this file
			//

			return TRUE;
		}
	}

	return FALSE;
}

BOOLEAN
ClaimsmanCheckUserIgnore(
_In_ PUNICODE_STRING User
)
/*++

Routine Description:

Checks if this user should be ignored

Arguments

Extension - Pointer to the SID

Return Value

TRUE - Yes ignore this user
FALSE - No
--*/
{
	PAGED_CODE();

	ULONG count;

	if (User == NULL || User->Length == 0) {

		return FALSE;
	}

	//
	//  Check if it matches any one of our static extension list
	//

	for (count = 0; count < ClaimsmanData.IgnoredUserCount; count++) {

		if (RtlCompareUnicodeString(User, ClaimsmanData.IgnoredUsers + count, TRUE) == 0) {

			//
			//  A match. Ignore this user
			//

			return TRUE;
		}
	}

	return FALSE;
}