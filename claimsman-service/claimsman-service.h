#ifndef __CLAIMSMAN_SERVICE_H__
#define __CLAIMSMAN_SERVICE_H__

#include <Windows.h>
#include <fltuser.h>
#include <string>
#include <concurrent_queue.h>

#define CLAIMSMAN_MESSAGE_FILENAME_SIZE   512
#define CLAIMSMAN_MESSAGE_SID_SIZE        256
#define CLAIMSMAN_MESSAGE_TIMESTAMP_SIZE  128

typedef struct _CLAIMSMAN_JSON_FIELDS {
	wchar_t *FileName;
	wchar_t *Sid;
	wchar_t *Username;
	wchar_t *TimeStamp;
	wchar_t *DNS;
	__int64 UnixTimeStamp;
	bool ReadAccess;
	bool WriteAccess;
	bool DeleteAccess;
	__int64 size;
	wchar_t *LastModified;
	__int64 UnixLastModified;
	bool loggedToFile;
	wchar_t *Status;
} CLAIMSMAN_JSON_FIELDS;

typedef struct _CLAIMSMAN_RUNTIME {

	// Name of this computer
	LPWSTR Name;

	// Target server
	std::wstring strLogServer;

	// Name of the log file
	std::wstring strLogFile;

	// Queue used for log data
	concurrency::concurrent_queue<CLAIMSMAN_JSON_FIELDS*> workQueue;

	// File for secondary logging
	HANDLE logFile;

} CLAIMSMAN_RUNTIME;

typedef struct _CLAIMSMAN_MESSAGE {

	// File name
	WCHAR FileName[CLAIMSMAN_MESSAGE_FILENAME_SIZE];

	// SID
	WCHAR Sid[CLAIMSMAN_MESSAGE_SID_SIZE];

	// TimeStamp
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
	__int64 UnixLastModified;
	// TimeStamp as ISO-8601
	WCHAR LastModified[CLAIMSMAN_MESSAGE_TIMESTAMP_SIZE];

	// IOStatus
	NTSTATUS Status;

} CLAIMSMAN_MESSAGE;

typedef struct _CLAIMSMAN_USER_MESSAGE {
	//
	//  Required structure header
	//

	FILTER_MESSAGE_HEADER MessageHeader;

	//
	//  Privatefields begin here
	//

	CLAIMSMAN_MESSAGE Message;

} CLAIMSMAN_USER_MESSAGE;

const PWSTR ClaimsmanPortName = L"\\ClaimsmanPort";

BOOL
getUser(
_In_ WCHAR* sidstr,
_Inout_ LPTSTR* AcctName,
_Inout_ LPTSTR* DomainName
);

#endif //  __CLAIMSMAN_SERVICE_H__
