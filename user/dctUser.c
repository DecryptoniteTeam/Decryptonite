/*++

Copyright (c) 1989-2002  Microsoft Corporation

Module Name:

dctUser.c

Abstract:

This file contains the implementation for the main function of the
user application piece of MiniSpy.  This function is responsible for
controlling the command mode available to the user to control the
kernel mode driver.

--*/

#include <DriverSpecs.h>
_Analysis_mode_(_Analysis_code_type_user_code_)

#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <assert.h>
#include "dctLog.h"
#include <strsafe.h>
#include "uthash.h"
#include <tchar.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <stdbool.h>

// Link with the Wintrust.lib file.
#pragma comment (lib, "wintrust")

#define _UNICODE 1
#define UNICODE 1


#define SUCCESS              0
#define USAGE_ERROR          1
#define EXIT_INTERPRETER     2
#define EXIT_PROGRAM         4

#define INTERPRETER_EXIT_COMMAND1 "go"
#define INTERPRETER_EXIT_COMMAND2 "g"
#define PROGRAM_EXIT_COMMAND      "exit"
#define CMDLINE_SIZE              256
#define NUM_PARAMS                40

#define DECRYPTONITE_NAME            L"Decryptonite"

WCHAR * Volume;
int IsPassive = 0;
int IsVerbose = 0;
int IsVeryVerbose = 0;
int IsTrackFileChanges = 0;

__pragma(warning(push))
__pragma(warning(disable:4996))

DWORD
InterpretCommand(
	_In_ int argc,
	_In_reads_(argc) char *argv[],
	_In_ PLOG_CONTEXT Context
);

VOID
ListDevices(
	VOID
);

int
EnablePrivileges(
	VOID
);

BOOL VerifyEmbeddedSignature(LPCWSTR pwszSourceFile)
{
	LONG lStatus;
	DWORD dwLastError;

	// Initialize the WINTRUST_FILE_INFO structure.

	WINTRUST_FILE_INFO FileData;
	memset(&FileData, 0, sizeof(FileData));
	FileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
	FileData.pcwszFilePath = pwszSourceFile;
	FileData.hFile = NULL;
	FileData.pgKnownSubject = NULL;

	/*
	WVTPolicyGUID specifies the policy to apply on the file
	WINTRUST_ACTION_GENERIC_VERIFY_V2 policy checks:

	1) The certificate used to sign the file chains up to a root
	certificate located in the trusted root certificate store. This
	implies that the identity of the publisher has been verified by
	a certification authority.

	2) In cases where user interface is displayed (which this example
	does not do), WinVerifyTrust will check for whether the
	end entity certificate is stored in the trusted publisher store,
	implying that the user trusts content from this publisher.

	3) The end entity certificate has sufficient permission to sign
	code, as indicated by the presence of a code signing EKU or no
	EKU.
	*/

	GUID WVTPolicyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	WINTRUST_DATA WinTrustData;

	// Initialize the WinVerifyTrust input data structure.

	// Default all fields to 0.
	memset(&WinTrustData, 0, sizeof(WinTrustData));

	WinTrustData.cbStruct = sizeof(WinTrustData);

	// Use default code signing EKU.
	WinTrustData.pPolicyCallbackData = NULL;

	// No data to pass to SIP.
	WinTrustData.pSIPClientData = NULL;

	// Disable WVT UI.
	WinTrustData.dwUIChoice = WTD_UI_NONE;

	// No revocation checking.
	WinTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;

	// Verify an embedded signature on a file.
	WinTrustData.dwUnionChoice = WTD_CHOICE_FILE;

	// Verify action.
	WinTrustData.dwStateAction = WTD_STATEACTION_VERIFY;

	// Verification sets this value.
	WinTrustData.hWVTStateData = NULL;

	// Not used.
	WinTrustData.pwszURLReference = NULL;

	// This is not applicable if there is no UI because it changes 
	// the UI to accommodate running applications instead of 
	// installing applications.
	WinTrustData.dwUIContext = 0;

	// Set pFile.
	WinTrustData.pFile = &FileData;

	// WinVerifyTrust verifies signatures as specified by the GUID 
	// and Wintrust_Data.
	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	switch (lStatus)
	{
	case ERROR_SUCCESS:
		/*
		Signed file:
		- Hash that represents the subject is trusted.

		- Trusted publisher without any verification errors.

		- UI was disabled in dwUIChoice. No publisher or
		time stamp chain errors.

		- UI was enabled in dwUIChoice and the user clicked
		"Yes" when asked to install and run the signed
		subject.
		*/
		wprintf_s(L"The file \"%s\" is signed and the signature "
			L"was verified.\n",
			pwszSourceFile);
		break;

	case TRUST_E_NOSIGNATURE:
		// The file was not signed or had a signature 
		// that was not valid.

		// Get the reason for no signature.
		dwLastError = GetLastError();
		if (TRUST_E_NOSIGNATURE == dwLastError ||
			TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
			TRUST_E_PROVIDER_UNKNOWN == dwLastError)
		{
			// The file was not signed.
			wprintf_s(L"The file \"%s\" is not signed.\n",
				pwszSourceFile);
		}
		else
		{
			// The signature was not valid or there was an error 
			// opening the file.
			wprintf_s(L"An unknown error occurred trying to "
				L"verify the signature of the \"%s\" file.\n",
				pwszSourceFile);
		}

		break;

	case TRUST_E_EXPLICIT_DISTRUST:
		// The hash that represents the subject or the publisher 
		// is not allowed by the admin or user.
		wprintf_s(L"The signature is present, but specifically "
			L"disallowed.\n");
		break;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		// The user clicked "No" when asked to install and run.
		wprintf_s(L"The signature is present, but not "
			L"trusted.\n");
		break;

	case CRYPT_E_SECURITY_SETTINGS:
		/*
		The hash that represents the subject or the publisher
		was not explicitly trusted by the admin and the
		admin policy has disabled user trust. No signature,
		publisher or time stamp errors.
		*/
		wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
			L"representing the subject or the publisher wasn't "
			L"explicitly trusted by the admin and admin policy "
			L"has disabled user trust. No signature, publisher "
			L"or timestamp errors.\n");
		break;

	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. lStatus contains the 
		// publisher or time stamp chain error.
		wprintf_s(L"Error is: 0x%x.\n",
			lStatus);
		break;
	}

	// Any hWVTStateData must be released by a call with close.
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	return true;
}

VOID
DisplayError(
	_In_ DWORD Code
)

/*++

Routine Description:

This routine will display an error message based off of the Win32 error
code that is passed in. This allows the user to see an understandable
error message instead of just the code.

Arguments:

Code - The error code to be translated.

Return Value:

None.

--*/

{
	WCHAR buffer[MAX_PATH] = { 0 };
	DWORD count;
	HMODULE module = NULL;
	HRESULT status;

	count = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		Code,
		0,
		buffer,
		sizeof(buffer) / sizeof(WCHAR),
		NULL);


	if (count == 0) {

		count = GetSystemDirectory(buffer,
			sizeof(buffer) / sizeof(WCHAR));

		if (count == 0 || count > sizeof(buffer) / sizeof(WCHAR)) {

			//
			//  In practice we expect buffer to be large enough to hold the 
			//  system directory path. 
			//

			printf("    Could not translate error: %d\n", Code);
			return;
		}


		status = StringCchCat(buffer,
			sizeof(buffer) / sizeof(WCHAR),
			L"\\fltlib.dll");

		if (status != S_OK) {

			printf("    Could not translate error: %d\n", Code);
			return;
		}

		module = LoadLibraryExW(buffer, NULL, LOAD_LIBRARY_AS_DATAFILE);

		//
		//  Translate the Win32 error code into a useful message.
		//

		count = FormatMessage(FORMAT_MESSAGE_FROM_HMODULE,
			module,
			Code,
			0,
			buffer,
			sizeof(buffer) / sizeof(WCHAR),
			NULL);

		if (module != NULL) {

			FreeLibrary(module);
		}

		//
		//  If we still couldn't resolve the message, generate a string
		//

		if (count == 0) {

			printf("    Could not translate error: %d\n", Code);
			return;
		}
	}

	//
	//  Display the translated error.
	//

	printf("    %ws\n", buffer);
}

//
//  Main uses a loop which has an assignment in the while 
//  conditional statement. Suppress the compiler's warning.
//

#pragma warning(push)
#pragma warning(disable:4706) // assignment within conditional expression

int _cdecl
main(
	_In_ int argc,
	_In_reads_(argc) char *argv[]
)
/*++

Routine Description:

Main routine for Decryptonite

Arguments:

Return Value:

--*/
{
	HANDLE port = INVALID_HANDLE_VALUE;
	HRESULT hResult = S_OK;
	DWORD result;
	ULONG threadId;
	HANDLE thread = NULL;
	LOG_CONTEXT context;
	CHAR inputChar;
	UCHAR buffer[1024];
	PFILTER_VOLUME_BASIC_INFORMATION volumeBuffer = (PFILTER_VOLUME_BASIC_INFORMATION)buffer;
	HANDLE volumeIterator = INVALID_HANDLE_VALUE;
	ULONG volumeBytesReturned;
	WCHAR driveLetter[15] = { 0 };
	WCHAR tmpDriveLetter[15] = { 0 };
	ULONG instanceCount;
	CHAR * attachDriveCommands[2];
	CHAR * previousDrives[30];
	attachDriveCommands[0] = "/a";
	int counter = 0;

	//
	//  Initialize handle in case of error
	//

	context.ShutDown = NULL;


	//
	// Loads title of our Grad Project
	//
 
	printf("\n\n");
                            
	printf(" _____                             _              _ _					\n");
	printf("|  __ \\                           | |            (_) |					\n");
	printf("| |  | | ___  ___ _ __ _   _ _ __ | |_ ___  _ __  _| |_ ___				\n");
	printf("| |  | |/ _ \\/ __| '__| | | | '_ \\| __/ _ \\| '_ \\| | __/ _ \\		\n");
	printf("| |__| |  __/ (__| |  | |_| | |_) | || (_) | | | | | ||  __/			\n");
	printf("|_____/ \\___|\\___|_|   \\__, | .__/ \\__\\___/|_| |_|_|\\__\\___|		\n");
	printf("                        __/ | |										\n");
	printf("                       |___/|_|									\n\n\n");

	printf("Adam Greenhill :: Christina Kang :: Desiree McCarthy :: Peter Chmura\n");

	printf("\n\n\n\n");

	Sleep(2500);

	//
	//  Attempting to load Minispy.
	//
	EnablePrivileges();
	printf("Attempting to load minifilter driver...\n");
	hResult = FilterLoad(L"decryptonite");
	if (HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) == hResult)
	{
		printf("The minifilter driver is already running...\n");
	}
	else if (HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) == hResult) {
		printf("No matching minifilter driver was found...\n");
	}
	else if (HRESULT_FROM_WIN32(ERROR_SERVICE_ALREADY_RUNNING) == hResult) {
		printf("The minifilter driver is already running...\n");
	}
	else if (HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT) == hResult) {
		printf("The load image for the minifilter driver specified by lpFilterName is invalid...\n");
	}
	else if (HRESULT_FROM_WIN32(ERROR_BAD_DRIVER) == hResult) {
		printf("The load image for the minifilter driver specified by lpFilterName is invalid...\n");
	}
	else if (HRESULT_FROM_WIN32(ERROR_INVALID_IMAGE_HASH) == hResult) {
		printf("The minifilter driver has an invalid digital signature...\n");
	}
	else if (hResult != S_OK)
	{
		printf("Unknown error occurred...\n");
	}
	else
	{
		printf("The minifilter driver has successfully been loaded.\n");
	}


	//
	//  Open the port that is used to talk to
	//  MiniSpy.
	//

	printf("Connecting to filter's port...\n");

	hResult = FilterConnectCommunicationPort(MINISPY_PORT_NAME,
		0,
		NULL,
		0,
		NULL,
		&port);

	if (IS_ERROR(hResult)) {

		printf("Could not connect to filter: 0x%08x\n", hResult);
		DisplayError(hResult);
		goto Main_Exit;
	}

	//
	// Initialize the fields of the LOG_CONTEXT
	//

	context.Port = port;
	context.ShutDown = CreateSemaphore(NULL,
		0,
		1,
		L"MiniSpy shut down");
	context.CleaningUp = FALSE;
	context.LogToFile = FALSE;
	context.LogToScreen = FALSE;        //don't start logging yet
	context.NextLogToScreen = TRUE;
	context.OutputFile = NULL;

	if (context.ShutDown == NULL) {

		result = GetLastError();
		printf("Could not create semaphore: %d\n", result);
		DisplayError(result);
		goto Main_Exit;
	}

	//
	// Check the valid parameters for startup
	//

	if (argc > 1) {

		if (InterpretCommand(argc - 1, &(argv[1]), &context) == USAGE_ERROR) {

			goto Main_Exit;
		}
	}

	//
	// Create the thread to read the log records that are gathered
	// by MiniSpy.sys.
	//
	printf("Creating logging thread...\n");
	thread = CreateThread(NULL,
		0,
		RetrieveLogRecords,
		(LPVOID)&context,
		0,
		&threadId);

	if (!thread) {

		result = GetLastError();
		printf("Could not create logging thread: %d\n", result);
		DisplayError(result);
		goto Main_Exit;
	}

	//
	// Check to see what devices we are attached to from
	// previous runs of this program.
	//

	printf("Detecting and attaching to drives...\n");

	try {

		//
		//  Find out size of buffer needed
		//

		hResult = FilterVolumeFindFirst(FilterVolumeBasicInformation,
			volumeBuffer,
			sizeof(buffer) - sizeof(WCHAR),   //save space to null terminate name
			&volumeBytesReturned,
			&volumeIterator);

		if (IS_ERROR(hResult)) {

			leave;
		}

		assert(INVALID_HANDLE_VALUE != volumeIterator);

		//
		//  Loop through all of the filters, displaying instance information
		//

		do {

			assert((FIELD_OFFSET(FILTER_VOLUME_BASIC_INFORMATION, FilterVolumeName) + volumeBuffer->FilterVolumeNameLength) <= (sizeof(buffer) - sizeof(WCHAR)));
			_Analysis_assume_((FIELD_OFFSET(FILTER_VOLUME_BASIC_INFORMATION, FilterVolumeName) + volumeBuffer->FilterVolumeNameLength) <= (sizeof(buffer) - sizeof(WCHAR)));

			volumeBuffer->FilterVolumeName[volumeBuffer->FilterVolumeNameLength / sizeof(WCHAR)] = UNICODE_NULL;

			instanceCount = IsAttachedToVolume(volumeBuffer->FilterVolumeName);

			SUCCEEDED(FilterGetDosName(
				volumeBuffer->FilterVolumeName,
				driveLetter,
				sizeof(driveLetter) / sizeof(WCHAR))) ? driveLetter : L"";
			__pragma(warning(push))
				__pragma(warning(disable:4133))
				if (strcmp(driveLetter, "") > 0 && PreviousDriveCheck(counter, previousDrives, driveLetter) == 1) {
					// command: /a C:
					// call to InterpretCommand(2, command, context);

					// Adds the volume that we are monitoring for our indicators
					if (!wcscmp(driveLetter, L"C:")) {
						Volume = (WCHAR *)malloc(sizeof(volumeBuffer->FilterVolumeName) + 16 * sizeof(WCHAR*));
						wcscpy(Volume, volumeBuffer->FilterVolumeName);
					}
					
					if (instanceCount == 0) {
						sprintf(tmpDriveLetter, "%ws", driveLetter);
						attachDriveCommands[1] = tmpDriveLetter;
						InterpretCommand(2, attachDriveCommands, &context);
					}
					else {
						printf("    OK: %ws is already being monitored...\n", driveLetter);
					}

					previousDrives[counter] = driveLetter;
					counter += 1;
				}
			__pragma(warning(pop))
		} while (SUCCEEDED(hResult = FilterVolumeFindNext(volumeIterator,
			FilterVolumeBasicInformation,
			volumeBuffer,
			sizeof(buffer) - sizeof(WCHAR),    //save space to null terminate name
			&volumeBytesReturned)));

			if (HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS) == hResult) {

				hResult = S_OK;
			}

	}
	finally {

		if (INVALID_HANDLE_VALUE != volumeIterator) {

			FilterVolumeFindClose(volumeIterator);
		}

		if (IS_ERROR(hResult)) {

			if (HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS) == hResult) {

				printf("No volumes found.\n");

			}
			else {

				printf("Volume listing failed with error: 0x%08x\n",
					hResult);
			}
		}
	}

	//
	//  Process commands from the user
	//

	Sleep(100);
	printf("\nHit [Enter] to begin command mode...\n\n");
	fflush(stdout);

	//
	//  set screen logging state
	//

	context.LogToScreen = context.NextLogToScreen;

	while (inputChar = (CHAR)getchar()) {

		CHAR *parms[NUM_PARAMS];
		CHAR commandLine[CMDLINE_SIZE + 1];
		INT parmCount, count;
		DWORD returnValue = SUCCESS;
		BOOL newParm;
		CHAR ch;

		if (inputChar == '\n') {

			//
			// Start command interpreter.  First we must turn off logging
			// to screen if we are.  Also, remember the state of logging
			// to the screen, so that we can reinstate that when command
			// interpreter is finished.
			//

			context.NextLogToScreen = context.LogToScreen;
			context.LogToScreen = FALSE;

			while (returnValue != EXIT_INTERPRETER) {

				//
				// Print prompt
				//
				printf(">");

				//
				// Read in next line, keeping track of the number of parameters
				// as we go.
				//

				parmCount = 0;
				newParm = TRUE;
				for (count = 0;
					(count < CMDLINE_SIZE) && ((ch = (CHAR)getchar()) != '\n');
					count++)
				{
					commandLine[count] = ch;

					if (newParm && (ch != ' ')) {

						parms[parmCount++] = &commandLine[count];
					}

					if (parmCount >= NUM_PARAMS) {

						break;
					}

					//
					//  Always insert NULL's for spaces
					//

					if (ch == ' ') {

						newParm = TRUE;
						commandLine[count] = 0;

					}
					else {

						newParm = FALSE;
					}
				}

				commandLine[count] = '\0';

				if (parmCount == 0) {

					continue;
				}

				//
				// We've got our parameter count and parameter list, so
				// send it off to be interpreted.
				//

				returnValue = InterpretCommand(parmCount, parms, &context);

				if (returnValue == EXIT_PROGRAM) {

					// Time to stop the program
					goto Main_Cleanup;
				}
			}

			//
			// Set LogToScreen appropriately based on any commands seen
			//

			context.LogToScreen = context.NextLogToScreen;

			if (context.LogToScreen) {

				printf("Should be logging to screen...\n");
			}
		}
	}

Main_Cleanup:

	//
	// Clean up the threads, then fall through to Main_Exit
	//

	printf("Cleaning up...\n");

	//
	// Set the Cleaning up flag to TRUE to notify other threads
	// that we are cleaning up
	//
	context.CleaningUp = TRUE;

	//
	// Wait for everyone to shut down
	//

	WaitForSingleObject(context.ShutDown, INFINITE);

	if (context.LogToFile) {

		fclose(context.OutputFile);
	}

Main_Exit:

	//
	// Clean up the data that is always around and exit
	//

	if (context.ShutDown) {

		CloseHandle(context.ShutDown);
	}

	if (thread) {

		CloseHandle(thread);
	}

	if (INVALID_HANDLE_VALUE != port) {
		CloseHandle(port);
	}
	return 0;
}

#pragma warning(pop)

DWORD
InterpretCommand(
	_In_ int argc,
	_In_reads_(argc) char *argv[],
	_In_ PLOG_CONTEXT Context
)
/*++

Routine Description:

Process options from the user

Arguments:

Return Value:

--*/
{
	LONG parmIndex;
	PCHAR parm;
	HRESULT hResult;
	DWORD returnValue = SUCCESS;
	CHAR buffer[BUFFER_SIZE];
	DWORD bufferLength;
	PWCHAR instanceString;
	WCHAR instanceName[INSTANCE_NAME_MAX_CHARS + 1];

	//
	// Interpret the command line parameters
	//
	for (parmIndex = 0; parmIndex < argc; parmIndex++) {

		parm = argv[parmIndex];

		if (parm[0] == '/') {

			//
			// Have the beginning of a switch
			//

			switch (parm[1]) {

			case 'a':
			case 'A':

				//
				// Attach to the specified drive letter
				//

				parmIndex++;

				if (parmIndex >= argc) {

					//
					// Not enough parameters
					//

					goto InterpretCommand_Usage;
				}

				parm = argv[parmIndex];

				printf("    Attaching to %s... ", parm);

				bufferLength = MultiByteToWideChar(CP_ACP,
					MB_ERR_INVALID_CHARS,
					parm,
					-1,
					(LPWSTR)buffer,
					BUFFER_SIZE / sizeof(WCHAR));

				if (bufferLength == 0) {

					//
					//  We do not expect the user to provide a parm that
					//  causes buffer to overflow. 
					//

					goto InterpretCommand_Usage;
				}

				hResult = FilterAttach(DECRYPTONITE_NAME,
					(PWSTR)buffer,
					NULL, // instance name
					sizeof(instanceName),
					instanceName);

				if (SUCCEEDED(hResult)) {

					printf("    Instance name: %S\n", instanceName);

				}
				else {

					printf("\n    Could not attach to device: 0x%08x\n", hResult);
					DisplayError(hResult);
					returnValue = SUCCESS;
				}

				break;

			case 'd':
			case 'D':

				//
				// Detach to the specified drive letter
				//

				parmIndex++;

				if (parmIndex >= argc) {

					//
					// Not enough parameters
					//

					goto InterpretCommand_Usage;
				}

				parm = argv[parmIndex];

				printf("    Detaching from %s\n", parm);
				bufferLength = MultiByteToWideChar(CP_ACP,
					MB_ERR_INVALID_CHARS,
					parm,
					-1,
					(LPWSTR)buffer,
					BUFFER_SIZE / sizeof(WCHAR));

				if (bufferLength == 0) {

					//
					//  We do not expect the user to provide a parm that
					//  causes buffer to overflow.
					//

					goto InterpretCommand_Usage;
				}

				//
				//  Get the next argument to see if it is an InstanceId
				//

				parmIndex++;

				if (parmIndex >= argc) {

					instanceString = NULL;

				}
				else {

					if (argv[parmIndex][0] == '/') {

						//
						//  This is just the next command, so don't
						//  internet it as the InstanceId.
						//

						instanceString = NULL;
						parmIndex--;

					}
					else {

						parm = argv[parmIndex];
						bufferLength = MultiByteToWideChar(CP_ACP,
							MB_ERR_INVALID_CHARS,
							parm,
							-1,
							(LPWSTR)instanceName,
							sizeof(instanceName) / sizeof(WCHAR));

						if (bufferLength == 0) {

							//
							//  We do not expect the user to provide a parm that
							//  causes buffer to overflow.
							//

							goto InterpretCommand_Usage;
						}

						instanceString = instanceName;
					}
				}

				//
				//  Detach from the volume and instance specified.
				//

				hResult = FilterDetach(DECRYPTONITE_NAME,
					(PWSTR)buffer,
					instanceString);

				if (IS_ERROR(hResult)) {

					printf("    Could not detach from device: 0x%08x\n", hResult);
					DisplayError(hResult);
					returnValue = SUCCESS;
				}
				break;

			case 'l':
			case 'L':

				//
				// List all devices that are currently being monitored
				//

				ListDevices();
				break;

			case 's':
			case 'S':

				//
				// Output logging results to screen, save new value to
				// instate when command interpreter is exited.
				//
				if (Context->NextLogToScreen) {

					printf("    Turning off logging to screen\n");

				}
				else {

					printf("    Turning on logging to screen\n");
				}

				Context->NextLogToScreen = !Context->NextLogToScreen;
				break;

			case 'p':
			case 'P':
				IsPassive = !IsPassive;
				if (IsPassive == 1) {
					printf("    Turning on passive mode\n");
				}
				else {
					printf("    Turning off passive mode\n");
				}
				break;
			case 'f':
			case 'F':

				//
				// Output logging results to file
				//

				if (Context->LogToFile) {

					printf("    Stop logging to file \n");
					Context->LogToFile = FALSE;
					assert(Context->OutputFile);
					_Analysis_assume_(Context->OutputFile != NULL);
					fclose(Context->OutputFile);
					Context->OutputFile = NULL;

				}
				else {

					parmIndex++;

					if (parmIndex >= argc) {

						//
						// Not enough parameters
						//

						goto InterpretCommand_Usage;
					}

					parm = argv[parmIndex];
					printf("    Log to file %s\n", parm);

					if (fopen_s(&Context->OutputFile, parm, "w") != 0) {
						assert(Context->OutputFile);
					}

					Context->LogToFile = TRUE;
				}
				break;
			case 'v':
			case 'V':
				printf("Verbose display turned on.\n");
				IsVerbose = 1;
				break;
			case 'x':
			case 'X':
				printf("Very verbose display turned on.\n");
				IsVeryVerbose = 1;
				break;

			default:

				//
				// Invalid switch, goto usage
				//
				goto InterpretCommand_Usage;
			}

		}
		else {

			//
			// Look for "go" or "g" to see if we should exit interpreter
			//

			if (!_strnicmp(parm,
				INTERPRETER_EXIT_COMMAND1,
				sizeof(INTERPRETER_EXIT_COMMAND1))) {

				returnValue = EXIT_INTERPRETER;
				goto InterpretCommand_Exit;
			}

			if (!_strnicmp(parm,
				INTERPRETER_EXIT_COMMAND2,
				sizeof(INTERPRETER_EXIT_COMMAND2))) {

				returnValue = EXIT_INTERPRETER;
				goto InterpretCommand_Exit;
			}

			//
			// Look for "exit" to see if we should exit program
			//

			if (!_strnicmp(parm,
				PROGRAM_EXIT_COMMAND,
				sizeof(PROGRAM_EXIT_COMMAND))) {

				returnValue = EXIT_PROGRAM;
				goto InterpretCommand_Exit;
			}

			//
			// Invalid parameter
			//
			goto InterpretCommand_Usage;
		}
	}

InterpretCommand_Exit:
	return returnValue;

InterpretCommand_Usage:
	printf("Valid switches: [/a <drive>] [/d <drive>] [/l] [/s] [/f [<file name>]] [/p] [/t] [/v] [/x]\n"
		"    [/a <drive>] starts monitoring <drive>\n"
		"    [/d <drive> [<instance id>]] detaches filter <instance id> from <drive>\n"
		"    [/l] lists all the drives the monitor is currently attached to\n"
		"    [/s] turns on and off showing logging output on the screen\n"
		"    [/f [<file name>]] turns on and off logging to the specified file\n"
		"    [/p] turns on passive mode (does not kill or whitelist processes)\n"
		"    [/v] display verbose output \n"
		"    [/x] display very verbose output \n"
		"  If you are in command mode:\n"
		"    [enter] will enter command mode\n"
		"    [go|g] will exit command mode\n"
		"    [exit] will terminate this program\n"
	);
	returnValue = USAGE_ERROR;
	goto InterpretCommand_Exit;
}


ULONG
IsAttachedToVolume(
	_In_ LPCWSTR VolumeName
)
/*++

Routine Description:

Determine if our filter is attached to this volume

Arguments:

VolumeName - The volume we are checking

Return Value:

TRUE - we are attached
FALSE - we are not attached (or we couldn't tell)

--*/
{
	PWCHAR filtername;
	CHAR buffer[1024];
	PINSTANCE_FULL_INFORMATION data = (PINSTANCE_FULL_INFORMATION)buffer;
	HANDLE volumeIterator = INVALID_HANDLE_VALUE;
	ULONG bytesReturned;
	ULONG instanceCount = 0;
	HRESULT hResult;

	//
	//  Enumerate all instances on this volume
	//

	hResult = FilterVolumeInstanceFindFirst(VolumeName,
		InstanceFullInformation,
		data,
		sizeof(buffer) - sizeof(WCHAR),
		&bytesReturned,
		&volumeIterator);

	if (IS_ERROR(hResult)) {

		return instanceCount;
	}

	do {

		assert((data->FilterNameBufferOffset + data->FilterNameLength) <= (sizeof(buffer) - sizeof(WCHAR)));
		_Analysis_assume_((data->FilterNameBufferOffset + data->FilterNameLength) <= (sizeof(buffer) - sizeof(WCHAR)));

		//
		//  Get the name.  Note that we are NULL terminating the buffer
		//  in place.  We can do this because we don't care about the other
		//  information and we have guaranteed that there is room for a NULL
		//  at the end of the buffer.
		//


		filtername = Add2Ptr(data, data->FilterNameBufferOffset);
		filtername[data->FilterNameLength / sizeof(WCHAR)] = L'\0';

		//
		//  Bump the instance count when we find a match
		//

		if (_wcsicmp(filtername, DECRYPTONITE_NAME) == 0) {

			instanceCount++;
		}

	} while (SUCCEEDED(FilterVolumeInstanceFindNext(volumeIterator,
		InstanceFullInformation,
		data,
		sizeof(buffer) - sizeof(WCHAR),
		&bytesReturned)));

	//
	//  Close the handle
	//

	FilterVolumeInstanceFindClose(volumeIterator);
	return instanceCount;
}


void
ListDevices(
	VOID
)
/*++

Routine Description:

Display the volumes we are attached to

Arguments:

Return Value:

--*/
{
	UCHAR buffer[1024];
	PFILTER_VOLUME_BASIC_INFORMATION volumeBuffer = (PFILTER_VOLUME_BASIC_INFORMATION)buffer;
	HANDLE volumeIterator = INVALID_HANDLE_VALUE;
	ULONG volumeBytesReturned;
	HRESULT hResult = S_OK;
	WCHAR driveLetter[15] = { 0 };
	ULONG instanceCount;

	try {

		//
		//  Find out size of buffer needed
		//

		hResult = FilterVolumeFindFirst(FilterVolumeBasicInformation,
			volumeBuffer,
			sizeof(buffer) - sizeof(WCHAR),   //save space to null terminate name
			&volumeBytesReturned,
			&volumeIterator);

		if (IS_ERROR(hResult)) {

			leave;
		}

		assert(INVALID_HANDLE_VALUE != volumeIterator);

		//
		//  Output the header
		//

		printf("\n"
			"Dos Name        Volume Name                            Status \n"
			"--------------  ------------------------------------  --------\n");

		//
		//  Loop through all of the filters, displaying instance information
		//

		do {

			assert((FIELD_OFFSET(FILTER_VOLUME_BASIC_INFORMATION, FilterVolumeName) + volumeBuffer->FilterVolumeNameLength) <= (sizeof(buffer) - sizeof(WCHAR)));
			_Analysis_assume_((FIELD_OFFSET(FILTER_VOLUME_BASIC_INFORMATION, FilterVolumeName) + volumeBuffer->FilterVolumeNameLength) <= (sizeof(buffer) - sizeof(WCHAR)));

			volumeBuffer->FilterVolumeName[volumeBuffer->FilterVolumeNameLength / sizeof(WCHAR)] = UNICODE_NULL;

			instanceCount = IsAttachedToVolume(volumeBuffer->FilterVolumeName);
			printf("%-14ws  %-36ws  %s",
				(SUCCEEDED(FilterGetDosName(
					volumeBuffer->FilterVolumeName,
					driveLetter,
					sizeof(driveLetter) / sizeof(WCHAR))) ? driveLetter : L""),
				volumeBuffer->FilterVolumeName,
				(instanceCount > 0) ? "Attached" : "");

			if (instanceCount > 1) {

				printf(" (%d)\n", instanceCount);

			}
			else {

				printf("\n");
			}

		} while (SUCCEEDED(hResult = FilterVolumeFindNext(volumeIterator,
			FilterVolumeBasicInformation,
			volumeBuffer,
			sizeof(buffer) - sizeof(WCHAR),    //save space to null terminate name
			&volumeBytesReturned)));

		if (HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS) == hResult) {

			hResult = S_OK;
		}

	}
	finally {

		if (INVALID_HANDLE_VALUE != volumeIterator) {

			FilterVolumeFindClose(volumeIterator);
		}

		if (IS_ERROR(hResult)) {

			if (HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS) == hResult) {

				printf("No volumes found.\n");

			}
			else {

				printf("Volume listing failed with error: 0x%08x\n",
					hResult);
			}
		}
	}
}

PreviousDriveCheck(int size, CHAR * previousDrives[30], WCHAR driveLetter[])
{
	int i = 0;
	for (; i < size; i++)
	{
		__pragma(warning(push))
			__pragma(warning(disable:4133))
			if (strcmp(previousDrives[i], driveLetter) == 0)
			{
				return 0;
			}
		__pragma(warning(pop))
	}
	return 1;
}

int EnablePrivileges()
{
	// 
	HANDLE hProcToken = 0;
	// Token privileges structure
	TOKEN_PRIVILEGES tkpPriv = { 0 };
	
	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hProcToken))
	{
		return USAGE_ERROR;
	}

	LookupPrivilegeValue(NULL, SE_LOAD_DRIVER_NAME, &tkpPriv.Privileges[0].Luid);

	// Count of privilege
	tkpPriv.PrivilegeCount = 1;

	// Set up "enable" attribute for privilege
	tkpPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Set up privilege
	AdjustTokenPrivileges(hProcToken, FALSE, &tkpPriv, 0, 0, 0);

	CloseHandle(hProcToken);

	return SUCCESS;
}