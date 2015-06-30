// claimsman-service.cpp : Service for receiving file access data from kernel and forwarding it
//

#include "stdafx.h"
#include "claimsman-service.h"
#include <Windows.h>
#include <process.h>
#include <fltUser.h>
#include <string>
#include <sddl.h>
#include <stdlib.h>
#include <concurrent_queue.h>
#include <cpprest/http_client.h>
#include <codecvt>
#include <iomanip>
#include <comdef.h>
// Casablanca
#include <cpprest/json.h>   
#include <cpprest/http_client.h> 
// Zlib
#include <zlib.h>

CLAIMSMAN_RUNTIME runtime;

#define CERT_STORE_NAME  L"MY"

void
freeJsonFields(
_Inout_ CLAIMSMAN_JSON_FIELDS *item
)
/*++

Routine Description:

Frees allocated fields of CLAIMSMAN_JSON_FIELDS

Arguments:

item - Pointer to CLAIMSMAN_JSON_FIELDS object.

Return Value:

No return value.

--*/
{
	if (item->DNS) {
		free(item->DNS);
	}
	if (item->FileName) {
		free(item->FileName);
	}
	if (item->Sid) {
		free(item->Sid);
	}
	if (item->TimeStamp) {
		free(item->TimeStamp);
	}
	if (item->Username) {
		GlobalFree(item->Username);
	}
	if (item->Status) {
		GlobalFree(item->Status);
	}
	free(item);
}

BOOL
buildGelf(
_In_ CLAIMSMAN_JSON_FIELDS *item,
_Inout_ web::json::value &gelf
)
/*++

Routine Description:

This routine builds JSON object that conforms to GELF.

Arguments:

item - Pointer to CLAIMSMAN_JSON_FIELDS object containing data.

gelf - Pointer to web::json::value object that will contain the JSON.

Return Value:

TRUE - Operation succeeded
FALSE - Operation failed

--*/
{
	try {
		// GELF spec version – “1.1”; MUST be set by client library.
		gelf[U("version")] = web::json::value::string(U("1.1"));
		// The name of the host, source or application that sent this message; MUST be set by client library.
		gelf[U("host")] = web::json::value::string(item->DNS);
		//a short descriptive message; MUST be set by client library.
		std::wstring description;
		description += L"Claimsman: ";
		description += item->Username;
		description += L" ";
		description += item->FileName;
		gelf[U("short_message")] = web::json::value::string(description);
		// Seconds since UNIX epoch with optional decimal places for milliseconds; SHOULD be set by client library. Will be set to NOW by server if absent.
		double ts;
		ts = (double)item->UnixTimeStamp / (double)1000;
		// Graylog automatically parses and converts this
		gelf[U("timestamp")] = web::json::value::number(ts);
		// ... But not this.
		gelf[U("_unixtimestamp")] = web::json::value::number(ts);
		// The level equal to the standard syslog levels; optional, default is 1 (ALERT).
		gelf[U("level")] = web::json::value::number(5); // NOTICE
		// Type for assisting in searching
		gelf[U("_logtype")] = web::json::value::string(U("claimsman"));
		gelf[U("_filename")] = web::json::value::string(item->FileName);
		gelf[U("_sid")] = web::json::value::string(item->Sid);
		gelf[U("_username")] = web::json::value::string(item->Username);
		gelf[U("_size")] = web::json::value::number(item->size);
		// Accesses
		if (item->ReadAccess) {
			gelf[U("_readaccess")] = web::json::value::string(U("true"));
		} 
		else {
			gelf[U("_readaccess")] = web::json::value::string(U("false"));
		}
		if (item->WriteAccess) {
			gelf[U("_writeaccess")] = web::json::value::string(U("true"));
		}
		else {
			gelf[U("_writeaccess")] = web::json::value::string(U("false"));
		}
		if (item->DeleteAccess) {
			gelf[U("_deleteaccess")] = web::json::value::string(U("true"));
		}
		else {
			gelf[U("_deleteaccess")] = web::json::value::string(U("false"));
		}
		
		// Last modified
		ts = (double)item->UnixLastModified / (double)1000;
		gelf[U("_unixlastmodified")] = web::json::value::number(ts);
		gelf[U("_lastmodified")] = web::json::value::string(item->LastModified);

		// Status
		gelf[U("_status")] = web::json::value::string(item->Status);

	}
	catch (const web::json::json_exception& e)
	{
		std::wostringstream ss;
		ss << e.what() << std::endl;
		std::wcout << L"buildGelf: " << ss.str();
		return FALSE;
	}

	std::wcout << gelf.serialize() << std::endl;
	return TRUE;
}

std::string
wstring_to_utf8(
const std::wstring& str
)
/*++

Routine Description:

Converts std::wstring to std::string containing UTF-8. Used with the compress_string to form a proper JSON message.

Arguments:

str - std::wstring containing Windows version of wide string

Return Value:

std::string - UTF-8 version of the str

--*/
{
	std::wstring_convert<std::codecvt_utf8<wchar_t>> myconv;
	return myconv.to_bytes(str);
}

std::string
compress_string(
const std::string& str,
int compressionlevel = Z_BEST_COMPRESSION
)
/*++

Routine Description:

Compresses std::string using zlib, based on common examples.

Arguments:

str - std:string to be compressed

compressionlevel - Z_BEST_COMPRESSION by default

Return Value:

std::string - zlib compressed string

--*/
{
	z_stream zs;
	memset(&zs, 0, sizeof(zs));

	if (deflateInit(&zs, compressionlevel) != Z_OK) {
		throw(std::runtime_error("deflateInit failed while compressing."));
	}

	zs.next_in = (Bytef*)str.data();
	zs.avail_in = (uInt)str.size();

	int ret;
	char outbuffer[12000];
	std::string outstring;

	do {
		zs.next_out = reinterpret_cast<Bytef*>(outbuffer);
		zs.avail_out = sizeof(outbuffer);

		ret = deflate(&zs, Z_FINISH);

		if (outstring.size() < zs.total_out) {
			outstring.append(outbuffer,
				zs.total_out - outstring.size());
		}
	} while (ret == Z_OK);

	deflateEnd(&zs);

	if (ret != Z_STREAM_END) {
		std::ostringstream oss;
		oss << "Exception during zlib compression: " << ret << " " << zs.msg;
		throw(std::runtime_error(oss.str()));
	}

	return outstring;
}


BOOL
compressGelf(
_In_ web::json::value &gelf,
_Inout_ std::string *compressed
)
/*++

Routine Description:

Compresses GELF by converting JSON string to UTF8, and using the zlib compression.

Arguments:

gelf - web::json::value representing JSON

compressed - Pointer std::string receiving result of the operation

Return Value:

TRUE - Operation succeeded

--*/
{
	std::wstring orig = std::wstring(gelf.serialize());
	std::string utf8 = wstring_to_utf8(orig);
	*compressed = compress_string(utf8);
	return TRUE;
}

std::string
ws2s(
const std::wstring& wstr
)
{
	typedef std::codecvt_utf8<wchar_t> convert_typeX;
	std::wstring_convert<convert_typeX, wchar_t> converterX;

	return converterX.to_bytes(wstr);
}

BOOLEAN
writeJSONLog(
_In_ utility::string_t json
)
/*++

Routine Description:

Writes the JSON to log file

Arguments:

json - String to be written

Return Value:

TRUE - Writing succeeded
FALSE - Writing failed

--*/
{
	std::string written;
	written += ws2s(json);
	written += "\n\n";


	BOOLEAN status = WriteFile(runtime.logFile,
		written.c_str(),
		(DWORD)strlen(written.c_str()),
		NULL,
		NULL
		);

	FlushFileBuffers(runtime.logFile);
	return status;
}

BOOLEAN
sendJSONLog(
_In_ web::json::value gelf
)
/*++

Routine Description:

Sends the JSON to log server

Arguments:

gelf - JSON to be sent

Return Value:

TRUE - Writing succeeded
FALSE - Writing failed

--*/
{
	BOOLEAN status = false;

	// Compress
	std::string compressed;
	compressGelf(gelf, &compressed);

	// Send log stuff
	web::http::client::http_client client(runtime.strLogServer);
	web::http::http_request requester;
	requester.set_body(compressed);
	requester.set_request_uri(L"/gelf");
	requester.set_method(web::http::methods::POST);
	requester.headers().set_content_type(U("text/plain; charset=utf-8"));
	pplx::task<web::http::http_response> task = client.request(requester);

	try
	{
		web::http::http_response respo = task.get();
		//std::wcout << respo.status_code();
		if (respo.status_code() == web::http::status_codes::Accepted) {
			// Only 202 should be sufficient
			status = true;
		}
	}
	catch (const std::exception& e)
	{
		// Unable to get confirmation of successful send!
		std::cout << e.what() << std::endl;
	}

	return status;
}

unsigned int
__stdcall
workerThread(void*)
/*++

Routine Description:

Worker thread that watches queue and sends the items.

Arguments:

None

Return Value:

unsigned int - Reserved for future use

--*/
{
	BOOL bErrorFlag = FALSE;
	CLAIMSMAN_JSON_FIELDS *item = NULL;
	DWORD written = 0x0;

	//
	// Prepare the local log file for writing
	//
	runtime.logFile = CreateFileA(ws2s(runtime.strLogFile).c_str(),
		GENERIC_WRITE,          // open for writing
		FILE_SHARE_READ,        // allow reading
		NULL,                   // default security
		OPEN_ALWAYS,            // opens a file, always
		FILE_ATTRIBUTE_NORMAL,  // normal file
		NULL);                  // no attr. template

	if (runtime.logFile == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("Terminal failure: Unable to open log file, terminating worker thread.\n"));
		return 0;
	}

	while (TRUE) {
		Sleep(500);
		if (runtime.workQueue.try_pop(item)) {
			bool success = false;

			// Build JSON object
			web::json::value gelf = web::json::value::object();
			if (buildGelf(item, gelf)) {

				// Write to log file, if not already written
				if (!item->loggedToFile)
					if (writeJSONLog(gelf.serialize())) {
						// Prevent re-writing this item
						item->loggedToFile = true;
					}
					else {
						std::cout << "failed to log " << std::endl;
					}

					// Send to log server
					if (sendJSONLog(gelf)) {
						success = true;
					}
			}
			else {
				std::cout << "Unable to build gelf!" << std::endl;
			}

			if (success == false) {
				// Re-input this item!
				runtime.workQueue.push(item);
			}
			else {
				// Free the item
				freeJsonFields(item);
			}
		}
	}

	return 0;
}

LPWSTR
getName()
/*++

Routine Description:

Get the name of this computer.

Arguments:

None

Return Value:

LPWSTR - Computer name, fqdn

--*/
{
	LPWSTR buffer = (LPTSTR)GlobalAlloc(GMEM_FIXED, (MAX_COMPUTERNAME_LENGTH + 1) * sizeof(TCHAR));
	DWORD length = MAX_COMPUTERNAME_LENGTH + 1;

	BOOL ok = GetComputerNameExW(ComputerNameDnsFullyQualified, buffer, &length);

	if (ok) {
		return buffer;
	}
	else {
		GlobalFree(buffer);
		return NULL;
	}
}

std::wstring 
GetErrorAsString
(
_In_ NTSTATUS status
)
/*++

Routine Description:

Formats NTSTATUS values (see ntstatus.h) as text.

Arguments:

status - The status value

Return Value:

std::wstring - NTSTATUS formatted as text.

--*/
{
	LPTSTR messageBuffer = nullptr;
	size_t size = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, status, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&messageBuffer, 0, NULL);
	std::wstring message(messageBuffer, size);
	//Free the buffer.
	LocalFree(messageBuffer);
	return message;
}

BOOLEAN
buildQueueObject(
_In_ wchar_t *FileName,
_In_ wchar_t *Sid,
_In_ wchar_t *Timestamp,
_In_ wchar_t *modified,
_In_ __int64 unixTimestamp,
_In_ __int64 unixModified,
_In_ __int64 size,
_In_ bool ReadAccess,
_In_ bool WriteAccess,
_In_ bool DeleteAccess,
_In_ NTSTATUS status,
_Inout_ CLAIMSMAN_JSON_FIELDS *object
)
/*++

Routine Description:

Builds object that can be put to the worker queue. Pre-processing point.

Arguments:

FileName - Pointer to wchar_t containing the filename
Sid - Pointer to wchar_t containing SID of the user
Timestamp - Pointer to wchar_t containing timestamp as ISO-8601
unixTimestamp - Unix time stamp of previous, with 3 digits for milliseconds
modified - Unix time stamp for last modified date, with 3 digits for milliseconds
size - Size of the file
ReadAccess - Was the file opened for read access?
WriteAccess - Was the file opened for write access?
DeleteAccess - Was the file opened for delete access?
object - Pointer to the object receiving pre-processed object

Return Value:

TRUE - operation succeeded
FALSE - operation failed

--*/
{
	// Duplicate the input strings
	object->FileName = _wcsdup(FileName);

	// Sid
	object->Sid = _wcsdup(Sid);

	// Username
	LPTSTR user = NULL;
	LPTSTR domain = NULL;
	if (getUser(Sid, &user, &domain)) {
		//_tprintf(TEXT("Username %s@%s\n"), user, domain);
		// + 1 for @, +1 for null terminator
		size_t len = (wcslen(user) + wcslen(domain) + 2) * sizeof(TCHAR);
		size_t lenw = (wcslen(user) + wcslen(domain) + 2);
		object->Username = (wchar_t*)GlobalAlloc(GMEM_FIXED, len);
		swprintf_s(object->Username, lenw, L"%s@%s", user, domain);
	}
	else {
		printf("Unable to get user data!");
		return false;
	};

	// Timestamp
	object->TimeStamp = _wcsdup(Timestamp);
	object->UnixTimeStamp = unixTimestamp;

	// Last modified
	object->UnixLastModified = unixModified;

	// Last modified string
	object->LastModified = _wcsdup(modified);

	// Accesses
	object->ReadAccess = ReadAccess;
	object->WriteAccess = WriteAccess;
	object->WriteAccess = WriteAccess;
	// Size
	object->size = size;

	// DNS name of this computer
	object->DNS = _wcsdup(runtime.Name);

	// Not written to log file yet
	object->loggedToFile = false;

	// Status
	std::wstring strStatus = GetErrorAsString(status);
	const wchar_t * tmp = strStatus.c_str();
	object->Status = (wchar_t*)GlobalAlloc(GMEM_FIXED, wcslen(tmp));
	object->Status = _wcsdup(tmp);
	
	GlobalFree(user);
	GlobalFree(domain);

	return true;
}

BOOL
getUser(
_In_ WCHAR *sidstr,
_Inout_ LPTSTR *AcctName,
_Inout_ LPTSTR *DomainName
)
/*++

Routine Description:

Converts a string representation of SID to string representation of username. Should query automatically AD for the information.

Arguments:

sidstr - Pointer to WCHAR representation of the SID
AcctName - Pointer to LPTSTR receiving the username
DomainName - Pointer to LPTSTR receiving the domain name

Return Value:

TRUE - operation succeeded
FALSE - operation failed

--*/
{
	PSID sid = NULL;
	DWORD dwAcctName = 0x0;
	DWORD dwDomainName = 0x0;
	SID_NAME_USE eUse = SidTypeUnknown;
	BOOL success;

	if (!ConvertStringSidToSidW(sidstr, &sid))
	{
		printf_s("ConvertStringSidToSid failed with 0x%08x\n", (int)GetLastError);
		return false;
	}

	// Lookup, the first one will always fail, returning how much memory should be allocated
	LookupAccountSidW(
		NULL,
		sid,
		*AcctName,
		&dwAcctName,
		*DomainName,
		&dwDomainName,
		&eUse);

	*AcctName = (LPTSTR)GlobalAlloc(GMEM_FIXED, dwAcctName * sizeof(TCHAR));
	*DomainName = (LPTSTR)GlobalAlloc(GMEM_FIXED, dwDomainName * sizeof(TCHAR));

	success = LookupAccountSidW(
		NULL,
		sid,
		*AcctName,
		&dwAcctName,
		*DomainName,
		&dwDomainName,
		&eUse);

	// In any case, not needed anymore
	if (sid) {
		LocalFree(sid);
	}

	if (!success) {
		printf_s("LookupAccountSid failed with 0x%08x\n", (int)GetLastError);
		return false;
	}

	return true;
}

LONG
GetStringRegKey(
HKEY hKey,
const std::wstring &strValueName,
std::wstring &strValue,
const std::wstring &strDefaultValue
)
/*++

Routine Description:

Gets a key from registry. If error happens, return a default value.

Arguments:

hKey - The registry key
strValueName - Name of the received value
strValue - Receives the value
strDefaultValue - Default value used in error situations

Return Value:

0 - OK
All the others - probably failure

--*/
{
	strValue = strDefaultValue;
	WCHAR szBuffer[512];
	DWORD dwBufferSize = sizeof(szBuffer);
	ULONG nError;
	nError = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);
	if (ERROR_SUCCESS == nError)
	{
		strValue = szBuffer;
	}
	return nError;
}

int
_tmain(
int argc,
_TCHAR* argv[]
)
/*++

Routine Description:

Main function for the service

Arguments:

argc - Number of arguments
argv - Array with pointers to arguments

Return Value:

0 - Normal exit
All the others - error
--*/
{
	HRESULT status;
	HANDLE port = NULL;
	CLAIMSMAN_USER_MESSAGE msg;

	// Get settings from registry
	HKEY hKey;
	LONG lRes = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Claimsman", 0, KEY_READ, &hKey);
	if (lRes != ERROR_SUCCESS) {
		printf("Unable to read settings from registry!\n");
		return 500;
	}

	GetStringRegKey(hKey, L"LogServer", runtime.strLogServer, L"");
	if (runtime.strLogServer == L"") {
		printf("Unable to read strLogServer from registry!\n");
		return 500;
	}

	GetStringRegKey(hKey, L"LogFile", runtime.strLogFile, L"");
	if (runtime.strLogFile == L"") {
		printf("Unable to read strLogFile from registry!\n");
		return 500;
	}

	// Get the name of this computer
	runtime.Name = getName();

	//  Open a communication channel to the filter

	printf("Claimsman-service: Connecting to the filter\n");

	status = FilterConnectCommunicationPort(ClaimsmanPortName,
		0,
		NULL,
		0,
		NULL,
		&port);

	if (IS_ERROR(status)) {
		printf("ERROR: Connecting to filter port: 0x%08x\n", status);
		return 2;
	}

	// Start background worker for handling events
	HANDLE worker;
	worker = (HANDLE)_beginthreadex(0, 0, &workerThread, (void*)0, 0, 0);


	// Fetch messages & handle them
	while (TRUE) {
		status = FilterGetMessage(port,
			&msg.MessageHeader,
			sizeof(msg),
			NULL
			);

		if (status == S_OK) {
			// Got a message successfully, build object to queue
			CLAIMSMAN_JSON_FIELDS *fields = (CLAIMSMAN_JSON_FIELDS*)malloc(sizeof(CLAIMSMAN_JSON_FIELDS));

			buildQueueObject(msg.Message.FileName,
				msg.Message.Sid,
				msg.Message.TimeStamp,
				msg.Message.LastModified,
				msg.Message.UnixTimeStamp,
				msg.Message.UnixLastModified,
				msg.Message.size,
				msg.Message.ReadAccess,
				msg.Message.WriteAccess,
				msg.Message.DeleteAccess,
				msg.Message.Status,
				fields);

			runtime.workQueue.push(fields);
			//_tprintf(TEXT("Work queue size: %u\n"), runtime.workQueue.unsafe_size());

		}
		else {
			printf("ERROR: GetMessage: 0x%08x\n", status);
		}
	}

	// Close the communication channel to the filter
	printf("Claimsman-service: Closing connection\n");
	CloseHandle(&port);
	CloseHandle(&worker);
	CloseHandle(&runtime.logFile);

	return 0;
}

