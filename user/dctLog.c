/*++

Copyright (c) 1989-2002  Microsoft Corporation

DECRYPTONITE
Sheridan College | ISS Captone Project

Module Name:

dctLog.c

Abstract:

This is a module that modifies functions used to retrieve and see the log records
recorded by MiniSpy.sys, and uses them to monitor file I/O activity on the machine, in order
to determine if ransomware exists on the host.

Altered By:

Adam Greenhill, Christina Kang, Desiree McCarthy, Peter Chmura

--*/

#include <DriverSpecs.h>
_Analysis_mode_(_Analysis_code_type_user_code_)

#include <stdio.h>
#include <windows.h>
#include <stdlib.h>
#include <winioctl.h>
#include <wchar.h>
#include "dctLog.h"
#include "uthash.h"
#include <ctype.h>
#include <string.h>
#include <tchar.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <Psapi.h>

// Link with the Wintrust.lib file.
#pragma comment (lib, "wintrust")

#define _UNICODE 1
#define UNICODE 1

#define TIME_BUFFER_LENGTH 20
#define TIME_ERROR         "time error"

#define POLL_INTERVAL   200     // 200 milliseconds

#define WHITELISTED 3
#define SYSTEMLISTED 2
#define GREYLISTED 1
#define TRACKED 0
#define UNTRACKED -1

#define SUCCESS 0
#define FAILURE 1

#define HIGH 25
#define MEDIUM 15	
#define LOW 5

#define THRESHOLD 100

#define BUFFER 255

#define TRUST_E_SELF_SIGNED_SIGNATURE 0x800b010aL

_In_ WCHAR relPath[MAX_PATH];
#define PATH_COUNT 3

__pragma(warning(push))
__pragma(warning(disable:4127))
__pragma(warning(disable:4996))

UT_icd ut_tm_icd = { sizeof(struct tm), NULL, NULL, NULL };

/*++

Routine Description:

If this is a mount point reparse point, move the given name string to the
correct position in the log record structure so it will be displayed
by the common routines.

Arguments:

logRecord - The log record to update

Return Value:

TRUE - if this is a mount point reparse point
FALSE - otherwise

--*/
BOOLEAN TranslateFileTag(_In_ PLOG_RECORD logRecord)
{
	PFLT_TAG_DATA_BUFFER TagData;
	ULONG Length;

	//
	// The reparse data structure starts in the NAME field, point to it.
	//

	TagData = (PFLT_TAG_DATA_BUFFER)&logRecord->Name[0];

	//
	//  See if MOUNT POINT tag
	//

	if (TagData->FileTag == IO_REPARSE_TAG_MOUNT_POINT) {

		//
		//  calculate how much to copy
		//

		Length = min(MAX_NAME_SPACE - sizeof(UNICODE_NULL), TagData->MountPointReparseBuffer.SubstituteNameLength);

		//
		//  Position the reparse name at the proper position in the buffer.
		//  Note that we are doing an overlapped copy
		//

		MoveMemory(&logRecord->Name[0],
			TagData->MountPointReparseBuffer.PathBuffer,
			Length);

		logRecord->Name[Length / sizeof(WCHAR)] = UNICODE_NULL;
		return TRUE;
	}

	return FALSE;
}

/*++

Routine Description:

This runs as a separate thread.  Its job is to retrieve log records
from the filter and then output them

Arguments:

lpParameter - Contains context structure for synchronizing with the
main program thread.

Return Value:

The thread successfully terminated

--*/

DWORD WINAPI RetrieveLogRecords(_In_ LPVOID lpParameter)
{
	PLOG_CONTEXT context = (PLOG_CONTEXT)lpParameter;
	DWORD bytesReturned = 0;
	DWORD used;
	PVOID alignedBuffer[BUFFER_SIZE / sizeof(PVOID)];
	PCHAR buffer = (PCHAR)alignedBuffer;
	HRESULT hResult;
	PLOG_RECORD pLogRecord;
	PRECORD_DATA pRecordData;
	COMMAND_MESSAGE commandMessage;
	__pragma(warning(push))
		__pragma(warning(disable:4189))
		struct ProcessThreatLevel * ProcessMap = NULL;
	struct ProcessThreatLevel * tmpProcess = NULL;
	struct HeuristicSignature * HeuristicMap = NULL;
	struct HeuristicSignature * tmpHeuristic = NULL;
	int * ProcessIds;
	int minispyPID = GetCurrentProcessId();
	int i;
	__pragma(warning(pop))
	int j;
	FILE *fp;
	int NewThreatLevel = 0;
	int parent = 0;
	int pid = 0;
	char *end;
	char buf[1035];
	char command[256];
	int parentwhitelistedStatus = 0;
	int childwhiteliststatus = -1;
	int currentwhiteliststatus = -1;
	int processDeadStatus = 0;
	int isPrivilegeEnabled = 0;
	struct ProcessThreatLevel * ptl;
	WCHAR volBuf[21][255];
	TCHAR path[MAX_PATH];
	BOOL whitelistProcess = FALSE;

	// Declaring and Intializing variables for Tracking File changes on the system
	struct tm lastChkTime;
	Array queueBucket;
	time_t rtime, now;

	int trackerSize = 0;
	int x = 0;
	int y = 0;
	int logging = 0;

	WCHAR * WhiteListedApplications[15] = { L"procexp.exe", L"procexp64.exe", L"csrss.exe", L"services.exe", L"dllhost.exe", L"DllHost.exe",
		L"Procmon.exe", L"Procmon64.exe", L"taskhost.exe", L"FrzState2k.exe", L"DFServ.exe", L"DFLocker64.exe", L"taskmgr.exe", L"SearchFilterHost.exe", L"conhost.exe" };
	WCHAR * SystemListedApplications[2] = { L"wininit.exe", L"explorer.exe" };

	Sleep(50);

	// Enabling Debug Privilieges 
	isPrivilegeEnabled = EnableDebugPrivileges();
	if (isPrivilegeEnabled == SUCCESS)
	{
		printf("SE_DEBUG_NAME privilege enabled.\n");
	}
	else
	{
		printf("SE_DEBUG_NAME privilege could not be enabled. Exiting\n");
		exit(1);
	}
	
	printf("\nEnabling Debug Privileges...");

	/*
		Initial Whitelisting
			Iterating through all system processes and categorizing them into whitelist categories
	*/
	printf("\nWhitelisting system applications...");
	TrackProcess(&ProcessMap, 0, 0, WHITELISTED);
	TrackProcess(&ProcessMap, 4, 0, SYSTEMLISTED);
	TrackProcess(&ProcessMap, GetCurrentProcessId(), 0, WHITELISTED);
	for (i = 0; i < (sizeof(WhiteListedApplications) / sizeof(WhiteListedApplications[0])); i++)
	{
		ProcessIds = GetPIDFromName(WhiteListedApplications[i]);
		for (j = 0; j < (sizeof(ProcessIds) / sizeof(ProcessIds[0])); j++)
		{
			TrackProcess(&ProcessMap, ProcessIds[j], 0, WHITELISTED);
		}
	}

	for (i = 0; i < (sizeof(SystemListedApplications) / sizeof(SystemListedApplications[0])); i++)
	{
		ProcessIds = GetPIDFromName(SystemListedApplications[i]);
		for (j = 0; j < (sizeof(ProcessIds) / sizeof(ProcessIds[0])); j++)
		{
			TrackProcess(&ProcessMap, ProcessIds[j], 0, SYSTEMLISTED);
		}
	}

	printf("\nWhitelisting non-system applications...");
	__pragma(warning(push))
		__pragma(warning(disable:4047))
		__pragma(warning(disable:4024))
		HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	__pragma(warning(pop))
		PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	while (hRes)
	{
		HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
			(DWORD)pEntry.th32ProcessID);
		GetFileNameFromPID(pEntry.th32ProcessID, &path);
		whitelistProcess = VerifyPESignature(path);
		wcscpy(path, "");
		if (whitelistProcess) {
			TrackProcess(&ProcessMap, pEntry.th32ProcessID, 0, WHITELISTED);
		}
		CloseHandle(hProcess);
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);



#pragma warning(push)
#pragma warning(disable:4133)
	PrintWhiteList(ProcessMap);

	printf("\nInitializing heuristics...");
	
	// Executable heuristics
	swprintf(volBuf[0], BUFFER, L"%ls%ls", Volume, L"\\Windows\\SysWOW64\\cmd.exe");
	TrackHeuristic(&HeuristicMap, volBuf[0], HIGH);
	swprintf(volBuf[1], BUFFER, L"%ls%ls", Volume, L"\\Windows\\System32\\cmd.exe");
	TrackHeuristic(&HeuristicMap, volBuf[1], HIGH);
	swprintf(volBuf[2], BUFFER, L"%ls%ls", Volume, L"\\Windows\\explorer.exe");
	TrackHeuristic(&HeuristicMap, volBuf[2], MEDIUM);
	swprintf(volBuf[3], BUFFER, L"%ls%ls", Volume, L"\\Windows\\System32\\taskmgr.exe");
	TrackHeuristic(&HeuristicMap, volBuf[3], MEDIUM);
	swprintf(volBuf[4], BUFFER, L"%ls%ls", Volume, L"\\Windows\\SysWOW64\\explorer.exe");
	TrackHeuristic(&HeuristicMap, volBuf[4], MEDIUM);
	swprintf(volBuf[5], BUFFER, L"%ls%ls", Volume, L"\\Windows\\SysWOW64\\reg.exe");
	TrackHeuristic(&HeuristicMap, volBuf[5], MEDIUM);
	swprintf(volBuf[6], BUFFER, L"%ls%ls", Volume, L"\\Windows\\SysWOW64\\vssadmin.exe");
	TrackHeuristic(&HeuristicMap, volBuf[6], HIGH);
	swprintf(volBuf[7], BUFFER, L"%ls%ls", Volume, L"\\Windows\\System32\\conhost.exe");
	TrackHeuristic(&HeuristicMap, volBuf[7], LOW);
	swprintf(volBuf[8], BUFFER, L"%ls%ls", Volume, L"\\Windows\\System32\\SearchFilterHost.exe");
	TrackHeuristic(&HeuristicMap, volBuf[8], LOW);
	swprintf(volBuf[9], BUFFER, L"%ls%ls", Volume, L"\\Windows\\System32\\unregmp2.exe");
	TrackHeuristic(&HeuristicMap, volBuf[9], LOW);
	swprintf(volBuf[10], BUFFER, L"%ls%ls", Volume, L"\\Windows\\SysWOW64\\wbem\\WMIC.exe");
	TrackHeuristic(&HeuristicMap, volBuf[10], MEDIUM);
	swprintf(volBuf[11], BUFFER, L"%ls%ls", Volume, L"\\Windows\\System32\\AdapterTroubleshooter.exe");
	TrackHeuristic(&HeuristicMap, volBuf[11], LOW);
	swprintf(volBuf[12], BUFFER, L"%ls%ls", Volume, L"\\Windows\\System32\\bootcfg.exe");
	TrackHeuristic(&HeuristicMap, volBuf[12], HIGH);
	swprintf(volBuf[13], BUFFER, L"%ls%ls", Volume, L"\\Windows\\System32\\bcdedit.exe");
	TrackHeuristic(&HeuristicMap, volBuf[13], HIGH);
	swprintf(volBuf[14], BUFFER, L"%ls%ls", Volume, L"\\Windows\\System32\\vssadmin.exe");
	TrackHeuristic(&HeuristicMap, volBuf[14], HIGH);
	// DLL heuristics
	swprintf(volBuf[15], BUFFER, L"%ls%ls", Volume, L"\\Windows\\SysWOW64\\rsaenh.dll");
	TrackHeuristic(&HeuristicMap, volBuf[15], HIGH);
	swprintf(volBuf[16], BUFFER, L"%ls%ls", Volume, L"\\Windows\\SysWOW64\\cryptsp.dll");
	TrackHeuristic(&HeuristicMap, volBuf[16], HIGH);
	swprintf(volBuf[17], BUFFER, L"%ls%ls", Volume, L"\\Windows\\System32\\cryptbase.dll");
	TrackHeuristic(&HeuristicMap, volBuf[17], HIGH);
	swprintf(volBuf[18], BUFFER, L"%ls%ls", Volume, L"\\Windows\\SysWOW64\\bcrypt.dll");
	TrackHeuristic(&HeuristicMap, volBuf[18], HIGH);
	swprintf(volBuf[19], BUFFER, L"%ls%ls", Volume, L"\\Windows\\System32\\cryptsp.dll");
	TrackHeuristic(&HeuristicMap, volBuf[19], HIGH);

	PrintHeuristics(HeuristicMap);

	// Intalize the array that hold the queue structures to tracking file 
	// changes for specific PIDs
	InitalizeArray(&queueBucket, TSIZE);

	// Adds an empty queue structure into the bucket for the first PID
	// that will be tracked
	struct PidChangeTracker pTracker = { 0, 0, 0, 0, 0, 0, 0, NULL };
	InsertElement(&queueBucket, &pTracker);

	// Grabs current time 
	time(&rtime);
	localtime_s(&lastChkTime, &rtime);

#pragma warning(push)
#pragma warning(disable:4127) // conditional expression is constant

	while (TRUE) {

#pragma warning(pop)

		//
		//  Check to see if we should shut down.
		//

		if (context->CleaningUp) {

			break;
		}

		//
		//  Request log data from MiniSpy.
		//

		commandMessage.Command = GetMiniSpyLog;

		hResult = FilterSendMessage(context->Port,
			&commandMessage,
			sizeof(COMMAND_MESSAGE),
			buffer,
			sizeof(alignedBuffer),
			&bytesReturned);

		if (IS_ERROR(hResult)) {

			if (HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE) == hResult) {

				printf("The kernel component of minispy has unloaded. Exiting\n");
				ExitProcess(0);
			}
			else {

				if (hResult != HRESULT_FROM_WIN32(ERROR_NO_MORE_ITEMS)) {

					printf("UNEXPECTED ERROR received: %x\n", hResult);
				}

				Sleep(POLL_INTERVAL);
			}

			continue;
		}

		//
		//  Buffer is filled with a series of LOG_RECORD structures, one
		//  right after another.  Each LOG_RECORD says how long it is, so
		//  we know where the next LOG_RECORD begins.
		//

		pLogRecord = (PLOG_RECORD)buffer;
		used = 0;

		//
		//  Logic to write record to screen and/or file
		//

		for (;;) {
			if (used + FIELD_OFFSET(LOG_RECORD, Name) > bytesReturned) {

				break;
			}

			if (pLogRecord->Length < (sizeof(LOG_RECORD) + sizeof(WCHAR))) {
#pragma warning(push)
#pragma warning(disable:4706)
				printf("UNEXPECTED LOG_RECORD->Length: length=%d expected>=%lld\n",
					pLogRecord->Length,
					(sizeof(LOG_RECORD) + sizeof(WCHAR)));

				break;
			}

			used += pLogRecord->Length;

			if (used > bytesReturned) {

				printf("UNEXPECTED LOG_RECORD size: used=%d bytesReturned=%d\n",
					used,
					bytesReturned);

				break;
			}

			pRecordData = &pLogRecord->Data;

			//
			//  See if a reparse point entry
			//

			if (FlagOn(pLogRecord->RecordType, RECORD_TYPE_FILETAG)) {

				if (!TranslateFileTag(pLogRecord)) {

					//
					// If this is a reparse point that can't be interpreted, move on.
					//

					pLogRecord = (PLOG_RECORD)Add2Ptr(pLogRecord, pLogRecord->Length);
					continue;
				}
			}

			// Checks if logging to screen is enabled --> needs to be here for now
			// we can remove this check all together once testing is complete
			if (context->LogToScreen) {
				logging = 1;
			}
			else {
				logging = 0;
			}

			//
			// if whitelisted
			//		this statement checks if a process is WHITELISTED or SYSTEMLISTED
			//		this statement will also determine if passive mode is turned on
			//		if either of these statements are true the application will ignore the behaviour
			//

			currentwhiteliststatus = IsWhiteListed(ProcessMap, pRecordData->ProcessId);
			if (!(currentwhiteliststatus == WHITELISTED || currentwhiteliststatus == SYSTEMLISTED) && isProcessDead(pRecordData->ProcessId) == FALSE && IsPassive == 0) {
				// Checks if the path that the process is working on is in our list of suspicious behaviours		
				if ((pRecordData->CallbackMajorId == IRP_MJ_CREATE || pRecordData->CallbackMajorId == 255) || pRecordData->CallbackMajorId == IRP_MJ_WRITE) {
					tmpHeuristic = FindHeuristic(HeuristicMap, pLogRecord->Name);
					if (tmpHeuristic != NULL || pRecordData->CallbackMajorId == IRP_MJ_WRITE) {
						pid = pRecordData->ProcessId;

						// find the parent process
						while (1) {
							// Determine if PID has digital signature early, whitelist it, and break out
							GetFileNameFromPID(pid, &path);
							whitelistProcess = VerifyPESignature(path);
							wcscpy(path, "");
							// if the process is whitelisted break out of the loop
							if (whitelistProcess) {
								if (logging) {
									printf("Whitelisting PID %d: Valid Digital Signature.\n", pid);
								}
								TrackProcess(&ProcessMap, pid, 0, WHITELISTED);
								parentwhitelistedStatus = WHITELISTED;
								break;
							}
							
							/* Open the command for reading. */
							sprintf(command, "wmic process where (processid=%lld) get parentprocessid 2> NUL", pid);
							fp = _popen(command, "r");
							if (fp == NULL) {
								if (logging) {
									printf("ERROR: Failed to run WMIC command.\n");
								}
								break;
							}

							/* Read the output a line at a time - output it. */
							while (fgets(buf, sizeof(buf) - 1, fp) != NULL) {
								if (isdigit(buf[0])) {
									parent = strtol(buf, &end, 10);
								}
							}
							/* close */
							_pclose(fp);

							// determine the whitelist category of the parent
							parentwhitelistedStatus = IsWhiteListed(ProcessMap, parent);
							
							// if a process is tracked break out of the loop
							if (currentwhiteliststatus == TRACKED) {
								parent = pid;
								break;
							}

							// determine if the parent is dead
							processDeadStatus = isProcessDead(parent);
							if ((parentwhitelistedStatus == TRACKED && processDeadStatus == FALSE)) {
								// Breaking out of the loop if it's tracked because we already have the information we need. Don't want to check again if parent is dead
								pid = parent;
								break;
							}
							// if the parent is whitelisted break out of the loop
							else if (parentwhitelistedStatus == WHITELISTED) {
								break;
							}
							// if the parent is system (e.g. Explorer.exe) track the process 
							else if (parentwhitelistedStatus == SYSTEMLISTED || pid == parent) {
								childwhiteliststatus = IsWhiteListed(ProcessMap, pid);
								if (childwhiteliststatus == UNTRACKED) {
									if (logging) {
										printf("Tracking PID %d: Parent %d is system or grey listed.\n", pid, parent);
									}
									GetFileNameFromPID(pid, &path);
									whitelistProcess = VerifyPESignature(path);
									wcscpy(path, "");
									if (whitelistProcess) {
										TrackProcess(&ProcessMap, pid, 0, WHITELISTED);
									}
									else {
										TrackProcess(&ProcessMap, pid, 0, TRACKED);
									}
								}

								break;
							}
							// if the process is greylisted break
							else if (currentwhiteliststatus == GREYLISTED) {
								
								break;
							}
							// in the event the process' parent switch focus to the child
							else if (processDeadStatus == TRUE) {
								HASH_FIND_INT(ProcessMap, &parent, tmpProcess); // Locate parent's process tracking information (may or may not exist)
								if (tmpProcess != NULL) { // if the parent was being tracked
									TrackProcess(&ProcessMap, pid, tmpProcess->dwThreatLevel, tmpProcess->dwIsWhiteListed); // child inherits dead parent's threat level, whitelist status
								}
								else { // if parent was not being tracked
									GetFileNameFromPID(pid, &path);
									whitelistProcess = VerifyPESignature(path); // check whitelist status of process
									wcscpy(path, ""); // clear path contents for next time
									if (whitelistProcess) {
										if (logging) {
											printf("Whitelisting PID %d: Valid Digital Signature.\n", pid);
										}
										TrackProcess(&ProcessMap, pid, 0, WHITELISTED);
										parentwhitelistedStatus = WHITELISTED;
									}
									else {
										TrackProcess(&ProcessMap, pid, 0, TRACKED); // parent is dead, and current process is not whitelisted
										parentwhitelistedStatus = TRACKED;
									}
								}
								parent = pid; // if the parent is dead, set process' parent to its own pid

								break;
							}
							else {
								// go up the process parent tree

								pid = parent;
							}

						}

						if (parentwhitelistedStatus != WHITELISTED) {
							/* Shades of Whitelisting code starts here */
							if (tmpHeuristic != NULL && (pRecordData->CallbackMajorId == IRP_MJ_CREATE || pRecordData->CallbackMajorId == 255)) {
								if (parentwhitelistedStatus == GREYLISTED) {
									NewThreatLevel = IncreaseThreatLevel(&ProcessMap, parent, tmpHeuristic->dwThreatLevel);
									if (logging) {
										printf("Suspicious behaviour: PID %d (%d%% ransomware likelihood)\n", pid, NewThreatLevel);
									}
									if (NewThreatLevel >= THRESHOLD) {
										if (logging) {
											printf("\nRANSOMWARE DETECTED: Killing process %lld.\n\n", parent);
										}
										HASH_FIND_INT(ProcessMap, &parent, ptl);
										if (ptl != NULL) {

											// For temporal activty tracking
											ClearPIDInfo(&queueBucket, parent);

											NewThreatLevel = 0;

											KillProcess(parent);
											UntrackProcess(&ProcessMap, parent);

										}
									}
								}
								// TRACKED or otherwise
								else {
									NewThreatLevel = IncreaseThreatLevel(&ProcessMap, pid, tmpHeuristic->dwThreatLevel);
									if (logging) {
										printf("Suspicious behaviour: PID %d (%d%% ransomware likelihood)\n", pid, NewThreatLevel);
									}

									if (NewThreatLevel >= THRESHOLD) {
										if (logging) {
											printf("\nRANSOMWARE DETECTED: Killing process %lld.\n\n", parent);
										}
										HASH_FIND_INT(ProcessMap, &pid, ptl);
										if (ptl != NULL) {
											// For temporal activty tracking
											ClearPIDInfo(&queueBucket, pid);

											NewThreatLevel = 0;

											KillProcess(pid);
											UntrackProcess(&ProcessMap, pid);

										}
									}
									tmpHeuristic = NULL;
								}
							}

							/* Temporal-Activity Tracking -
							Add a new timestamp for each indicator fed from minispy into seperate queue for each unique PID */
							if (pRecordData->CallbackMajorId == IRP_MJ_WRITE) {
								// Tracks file changes if the PID is writing to files on the system and is not whitelisted
								time_t now;
								struct tm timestamp;
								
								// Checks the queue bucket to see if the particular PID is being tracked for 
								// file changes
								for (x = 0; x < queueBucket.used; x++) {
									time(&now);
									// Checks to see if PID already exists in one of the queues
									if (queueBucket.array[x].pid == pid) {
										
										// Grabs the current time and converts to type struct tm
										timestamp = *localtime(&now);

										// Pushes a new timestamp for the specfic PID
										utarray_push_back(queueBucket.array[x].queue, &timestamp);

										// Increases the size of the queue by one, when new timestamp is inserted
										queueBucket.array[x].size += 1;

										break;
									}
									// Otherwise the new PID is inserted into the queue bucket and tracked
									// for file changes
									else if (queueBucket.array[x].size == 0 && queueBucket.array[x].pid == 0) {
										// Initializes an new queue in memoty for the particular PID
										utarray_new(queueBucket.array[x].queue, &ut_tm_icd);

										timestamp = *localtime(&now);
										utarray_push_back(queueBucket.array[x].queue, &timestamp);

										// Adds the new PID to the file change tracker 
										queueBucket.array[x].pid = pid;
										queueBucket.array[x].size = 1;
										trackerSize++;

										// Adds another empty queue, for another unique PID entry
										struct PidChangeTracker pTracker = { 0, 0, 0, 0, 0, 0, 0, NULL };
										InsertElement(&queueBucket, &pTracker);

										break;
									}
								}
							}
						}
					}
				}
			}

			/* Periodic checking to see the status of each queue
			for Temporal-Activity Tracking */
			time(&now);

			// Checks the status of each queue per second
			if (difftime(now, mktime(&lastChkTime)) >= 1) {

				// Loops through all the PID queues entires in the bucket making changes to files on the
				// system, checking their current status
				for (x = 0; x < trackerSize; x++) {
					if (queueBucket.array[x].size > 0) {
						
						// Resets the isHigh, isMedium, isLow checks for the particular PID every 5 seconds
						if (!(queueBucket.array[x].checks % 5)) {
							queueBucket.array[x].isHigh = 0;
							queueBucket.array[x].isMedium = 0;
							queueBucket.array[x].isLow = 0;
						}

						// Checks current writes per minute and whether and if isLow, isMedium, or isHigh is set
						if (queueBucket.array[x].writesPerSec >= 8 && !queueBucket.array[x].isHigh) {
							NewThreatLevel = IncreaseThreatLevel(&ProcessMap, queueBucket.array[x].pid, HIGH);
							queueBucket.array[x].isHigh = 1;
							if (logging) {
								printf("File writes [high - %2.2f/s]: PID %d (%d%% ransomware likelihood)\n", queueBucket.array[x].writesPerSec, pid, NewThreatLevel);
							}
						}
						else if (queueBucket.array[x].writesPerSec >= 3 && !queueBucket.array[x].isMedium) {
							NewThreatLevel = IncreaseThreatLevel(&ProcessMap, queueBucket.array[x].pid, MEDIUM);
							queueBucket.array[x].isMedium = 1;
							if (logging) {
								printf("File writes [medium - %2.2f/s]: PID %d (%d%% ransomware likelihood)\n", queueBucket.array[x].writesPerSec, pid, NewThreatLevel);
							}
						}
						else if (queueBucket.array[x].writesPerSec >= 1 && !queueBucket.array[x].isLow) {
							NewThreatLevel = IncreaseThreatLevel(&ProcessMap, queueBucket.array[x].pid, LOW);
							queueBucket.array[x].isLow = 1;
							if (logging) {
								printf("File writes [low - %2.2f/s]: PID %d (%d%% ransomware likelihood)\n", queueBucket.array[x].writesPerSec, pid, NewThreatLevel);
							}
						}

						// Removes all timestamp entries for the specfic PID, that are over 30 seconds old
						CleanUpQueue(&queueBucket.array[x]);

						if (parentwhitelistedStatus == GREYLISTED) {
							if (NewThreatLevel >= THRESHOLD) {
								if (logging) {
									printf("\nRANSOMWARE DETECTED: Killing process %lld.\n\n", parent);
								}

								HASH_FIND_INT(ProcessMap, &parent, ptl);

								if (ptl != NULL) {
									// For temporal activty tracking
									ClearPIDInfo(&queueBucket, parent);

									NewThreatLevel = 0;

									KillProcess(parent);
									UntrackProcess(&ProcessMap, parent);
								}
							}

							break;
						}
						// TRACKED or otherwise
						else {
							if (NewThreatLevel >= THRESHOLD) {
								if (logging) {
									printf("\nRANSOMWARE DETECTED: Killing process %lld.\n\n", parent);
								}
								HASH_FIND_INT(ProcessMap, &pid, ptl);
								if (ptl != NULL) {

									// For temporal activty tracking
									ClearPIDInfo(&queueBucket, pid);

									NewThreatLevel = 0;

									KillProcess(pid);
									UntrackProcess(&ProcessMap, pid);

								}
							}

							break;
						}

					}
					else {
						if (queueBucket.array[x].checks > 0) {
							queueBucket.array[x].checks++;
						}
					}
				}

				// Resets the last check time to the current time
				time(&rtime);
				localtime_s(&lastChkTime, &rtime);
			}

			if (IsVeryVerbose == 1 || IsPassive == 1) {
				if (context->LogToScreen) {

					ScreenDump(pLogRecord->SequenceNumber,
						pLogRecord->Name,
						pRecordData);
				}

				if (context->LogToFile) {

					FileDump(pLogRecord->SequenceNumber,
						pLogRecord->Name,
						pRecordData,
						context->OutputFile);
				}
			}

			//
			//  The RecordType could also designate that we are out of memory
			//  or hit our program defined memory limit, so check for these
			//  cases.
			//

			if (FlagOn(pLogRecord->RecordType, RECORD_TYPE_FLAG_OUT_OF_MEMORY)) {

				if (context->LogToScreen) {

					printf("M:  %08X System Out of Memory\n",
						pLogRecord->SequenceNumber);
				}

				if (context->LogToFile) {

					fprintf(context->OutputFile,
						"M:\t0x%08X\tSystem Out of Memory\n",
						pLogRecord->SequenceNumber);
				}

			}
			else if (FlagOn(pLogRecord->RecordType, RECORD_TYPE_FLAG_EXCEED_MEMORY_ALLOWANCE) && (IsVerbose || IsVeryVerbose)) {

				if (context->LogToScreen) {

					printf("M:  %08X Exceeded Mamimum Allowed Memory Buffers\n",
						pLogRecord->SequenceNumber);
				}

				if (context->LogToFile) {

					fprintf(context->OutputFile,
						"M:\t0x%08X\tExceeded Mamimum Allowed Memory Buffers\n",
						pLogRecord->SequenceNumber);
				}
			}

			//
			// Move to next LOG_RECORD
			//

			pLogRecord = (PLOG_RECORD)Add2Ptr(pLogRecord, pLogRecord->Length);

		}

		//
		//  If we didn't get any data, pause for 1/2 second
		//

		if (bytesReturned == 0) {

			Sleep(POLL_INTERVAL);
		}
	}

	// Frees all allocated space to the queue when program done executing
	for (y = 0; y < trackerSize; y++) {
		utarray_free(queueBucket.array[y].queue);
	}

	printf("Log: Shutting down\n");
	ReleaseSemaphore(context->ShutDown, 1, NULL);
	printf("Log: All done\n");
	return 0;
}

/*++

Routine Description:

Display the operation code

Arguments:

MajorCode - Major function code of operation

MinorCode - Minor function code of operation

OutputFile - If writing to a file (not the screen) the handle for that file

PrintMajorCode - Only used when printing to the display:
TRUE - if we want to display the MAJOR CODE
FALSE - if we want to display the MINOR code

Return Value:

None

--*/
VOID PrintIrpCode(_In_ UCHAR MajorCode, _In_ UCHAR MinorCode, _In_opt_ FILE *OutputFile, _In_ BOOLEAN PrintMajorCode)
{
	CHAR *irpMajorString, *irpMinorString = NULL;
	CHAR errorBuf[128];

	switch (MajorCode) {
	case IRP_MJ_CREATE:
		irpMajorString = IRP_MJ_CREATE_STRING;
		break;
	case IRP_MJ_CREATE_NAMED_PIPE:
		irpMajorString = IRP_MJ_CREATE_NAMED_PIPE_STRING;
		break;
	case IRP_MJ_CLOSE:
		irpMajorString = IRP_MJ_CLOSE_STRING;
		break;
	case IRP_MJ_READ:
		irpMajorString = IRP_MJ_READ_STRING;
		switch (MinorCode) {
		case IRP_MN_NORMAL:
			irpMinorString = IRP_MN_NORMAL_STRING;
			break;
		case IRP_MN_DPC:
			irpMinorString = IRP_MN_DPC_STRING;
			break;
		case IRP_MN_MDL:
			irpMinorString = IRP_MN_MDL_STRING;
			break;
		case IRP_MN_COMPLETE:
			irpMinorString = IRP_MN_COMPLETE_STRING;
			break;
		case IRP_MN_COMPRESSED:
			irpMinorString = IRP_MN_COMPRESSED_STRING;
			break;
		case IRP_MN_MDL_DPC:
			irpMinorString = IRP_MN_MDL_DPC_STRING;
			break;
		case IRP_MN_COMPLETE_MDL:
			irpMinorString = IRP_MN_COMPLETE_MDL_STRING;
			break;
		case IRP_MN_COMPLETE_MDL_DPC:
			irpMinorString = IRP_MN_COMPLETE_MDL_DPC_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_WRITE:
		irpMajorString = IRP_MJ_WRITE_STRING;
		switch (MinorCode) {
		case IRP_MN_NORMAL:
			irpMinorString = IRP_MN_NORMAL_STRING;
			break;
		case IRP_MN_DPC:
			irpMinorString = IRP_MN_DPC_STRING;
			break;
		case IRP_MN_MDL:
			irpMinorString = IRP_MN_MDL_STRING;
			break;
		case IRP_MN_COMPLETE:
			irpMinorString = IRP_MN_COMPLETE_STRING;
			break;
		case IRP_MN_COMPRESSED:
			irpMinorString = IRP_MN_COMPRESSED_STRING;
			break;
		case IRP_MN_MDL_DPC:
			irpMinorString = IRP_MN_MDL_DPC_STRING;
			break;
		case IRP_MN_COMPLETE_MDL:
			irpMinorString = IRP_MN_COMPLETE_MDL_STRING;
			break;
		case IRP_MN_COMPLETE_MDL_DPC:
			irpMinorString = IRP_MN_COMPLETE_MDL_DPC_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_QUERY_INFORMATION:
		irpMajorString = IRP_MJ_QUERY_INFORMATION_STRING;
		break;
	case IRP_MJ_SET_INFORMATION:
		irpMajorString = IRP_MJ_SET_INFORMATION_STRING;
		break;
	case IRP_MJ_QUERY_EA:
		irpMajorString = IRP_MJ_QUERY_EA_STRING;
		break;
	case IRP_MJ_SET_EA:
		irpMajorString = IRP_MJ_SET_EA_STRING;
		break;
	case IRP_MJ_FLUSH_BUFFERS:
		irpMajorString = IRP_MJ_FLUSH_BUFFERS_STRING;
		break;
	case IRP_MJ_QUERY_VOLUME_INFORMATION:
		irpMajorString = IRP_MJ_QUERY_VOLUME_INFORMATION_STRING;
		break;
	case IRP_MJ_SET_VOLUME_INFORMATION:
		irpMajorString = IRP_MJ_SET_VOLUME_INFORMATION_STRING;
		break;
	case IRP_MJ_DIRECTORY_CONTROL:
		irpMajorString = IRP_MJ_DIRECTORY_CONTROL_STRING;
		switch (MinorCode) {
		case IRP_MN_QUERY_DIRECTORY:
			irpMinorString = IRP_MN_QUERY_DIRECTORY_STRING;
			break;
		case IRP_MN_NOTIFY_CHANGE_DIRECTORY:
			irpMinorString = IRP_MN_NOTIFY_CHANGE_DIRECTORY_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_FILE_SYSTEM_CONTROL:
		irpMajorString = IRP_MJ_FILE_SYSTEM_CONTROL_STRING;
		switch (MinorCode) {
		case IRP_MN_USER_FS_REQUEST:
			irpMinorString = IRP_MN_USER_FS_REQUEST_STRING;
			break;
		case IRP_MN_MOUNT_VOLUME:
			irpMinorString = IRP_MN_MOUNT_VOLUME_STRING;
			break;
		case IRP_MN_VERIFY_VOLUME:
			irpMinorString = IRP_MN_VERIFY_VOLUME_STRING;
			break;
		case IRP_MN_LOAD_FILE_SYSTEM:
			irpMinorString = IRP_MN_LOAD_FILE_SYSTEM_STRING;
			break;
		case IRP_MN_TRACK_LINK:
			irpMinorString = IRP_MN_TRACK_LINK_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_DEVICE_CONTROL:
		irpMajorString = IRP_MJ_DEVICE_CONTROL_STRING;
		switch (MinorCode) {
		case IRP_MN_SCSI_CLASS:
			irpMinorString = IRP_MN_SCSI_CLASS_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_INTERNAL_DEVICE_CONTROL:
		irpMajorString = IRP_MJ_INTERNAL_DEVICE_CONTROL_STRING;
		break;
	case IRP_MJ_SHUTDOWN:
		irpMajorString = IRP_MJ_SHUTDOWN_STRING;
		break;
	case IRP_MJ_LOCK_CONTROL:
		irpMajorString = IRP_MJ_LOCK_CONTROL_STRING;
		switch (MinorCode) {
		case IRP_MN_LOCK:
			irpMinorString = IRP_MN_LOCK_STRING;
			break;
		case IRP_MN_UNLOCK_SINGLE:
			irpMinorString = IRP_MN_UNLOCK_SINGLE_STRING;
			break;
		case IRP_MN_UNLOCK_ALL:
			irpMinorString = IRP_MN_UNLOCK_ALL_STRING;
			break;
		case IRP_MN_UNLOCK_ALL_BY_KEY:
			irpMinorString = IRP_MN_UNLOCK_ALL_BY_KEY_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_CLEANUP:
		irpMajorString = IRP_MJ_CLEANUP_STRING;
		break;
	case IRP_MJ_CREATE_MAILSLOT:
		irpMajorString = IRP_MJ_CREATE_MAILSLOT_STRING;
		break;
	case IRP_MJ_QUERY_SECURITY:
		irpMajorString = IRP_MJ_QUERY_SECURITY_STRING;
		break;
	case IRP_MJ_SET_SECURITY:
		irpMajorString = IRP_MJ_SET_SECURITY_STRING;
		break;
	case IRP_MJ_POWER:
		irpMajorString = IRP_MJ_POWER_STRING;
		switch (MinorCode) {
		case IRP_MN_WAIT_WAKE:
			irpMinorString = IRP_MN_WAIT_WAKE_STRING;
			break;
		case IRP_MN_POWER_SEQUENCE:
			irpMinorString = IRP_MN_POWER_SEQUENCE_STRING;
			break;
		case IRP_MN_SET_POWER:
			irpMinorString = IRP_MN_SET_POWER_STRING;
			break;
		case IRP_MN_QUERY_POWER:
			irpMinorString = IRP_MN_QUERY_POWER_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_SYSTEM_CONTROL:
		irpMajorString = IRP_MJ_SYSTEM_CONTROL_STRING;
		switch (MinorCode) {
		case IRP_MN_QUERY_ALL_DATA:
			irpMinorString = IRP_MN_QUERY_ALL_DATA_STRING;
			break;
		case IRP_MN_QUERY_SINGLE_INSTANCE:
			irpMinorString = IRP_MN_QUERY_SINGLE_INSTANCE_STRING;
			break;
		case IRP_MN_CHANGE_SINGLE_INSTANCE:
			irpMinorString = IRP_MN_CHANGE_SINGLE_INSTANCE_STRING;
			break;
		case IRP_MN_CHANGE_SINGLE_ITEM:
			irpMinorString = IRP_MN_CHANGE_SINGLE_ITEM_STRING;
			break;
		case IRP_MN_ENABLE_EVENTS:
			irpMinorString = IRP_MN_ENABLE_EVENTS_STRING;
			break;
		case IRP_MN_DISABLE_EVENTS:
			irpMinorString = IRP_MN_DISABLE_EVENTS_STRING;
			break;
		case IRP_MN_ENABLE_COLLECTION:
			irpMinorString = IRP_MN_ENABLE_COLLECTION_STRING;
			break;
		case IRP_MN_DISABLE_COLLECTION:
			irpMinorString = IRP_MN_DISABLE_COLLECTION_STRING;
			break;
		case IRP_MN_REGINFO:
			irpMinorString = IRP_MN_REGINFO_STRING;
			break;
		case IRP_MN_EXECUTE_METHOD:
			irpMinorString = IRP_MN_EXECUTE_METHOD_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;

	case IRP_MJ_DEVICE_CHANGE:
		irpMajorString = IRP_MJ_DEVICE_CHANGE_STRING;
		break;
	case IRP_MJ_QUERY_QUOTA:
		irpMajorString = IRP_MJ_QUERY_QUOTA_STRING;
		break;
	case IRP_MJ_SET_QUOTA:
		irpMajorString = IRP_MJ_SET_QUOTA_STRING;
		break;
	case IRP_MJ_PNP:
		irpMajorString = IRP_MJ_PNP_STRING;
		switch (MinorCode) {
		case IRP_MN_START_DEVICE:
			irpMinorString = IRP_MN_START_DEVICE_STRING;
			break;
		case IRP_MN_QUERY_REMOVE_DEVICE:
			irpMinorString = IRP_MN_QUERY_REMOVE_DEVICE_STRING;
			break;
		case IRP_MN_REMOVE_DEVICE:
			irpMinorString = IRP_MN_REMOVE_DEVICE_STRING;
			break;
		case IRP_MN_CANCEL_REMOVE_DEVICE:
			irpMinorString = IRP_MN_CANCEL_REMOVE_DEVICE_STRING;
			break;
		case IRP_MN_STOP_DEVICE:
			irpMinorString = IRP_MN_STOP_DEVICE_STRING;
			break;
		case IRP_MN_QUERY_STOP_DEVICE:
			irpMinorString = IRP_MN_QUERY_STOP_DEVICE_STRING;
			break;
		case IRP_MN_CANCEL_STOP_DEVICE:
			irpMinorString = IRP_MN_CANCEL_STOP_DEVICE_STRING;
			break;
		case IRP_MN_QUERY_DEVICE_RELATIONS:
			irpMinorString = IRP_MN_QUERY_DEVICE_RELATIONS_STRING;
			break;
		case IRP_MN_QUERY_INTERFACE:
			irpMinorString = IRP_MN_QUERY_INTERFACE_STRING;
			break;
		case IRP_MN_QUERY_CAPABILITIES:
			irpMinorString = IRP_MN_QUERY_CAPABILITIES_STRING;
			break;
		case IRP_MN_QUERY_RESOURCES:
			irpMinorString = IRP_MN_QUERY_RESOURCES_STRING;
			break;
		case IRP_MN_QUERY_RESOURCE_REQUIREMENTS:
			irpMinorString = IRP_MN_QUERY_RESOURCE_REQUIREMENTS_STRING;
			break;
		case IRP_MN_QUERY_DEVICE_TEXT:
			irpMinorString = IRP_MN_QUERY_DEVICE_TEXT_STRING;
			break;
		case IRP_MN_FILTER_RESOURCE_REQUIREMENTS:
			irpMinorString = IRP_MN_FILTER_RESOURCE_REQUIREMENTS_STRING;
			break;
		case IRP_MN_READ_CONFIG:
			irpMinorString = IRP_MN_READ_CONFIG_STRING;
			break;
		case IRP_MN_WRITE_CONFIG:
			irpMinorString = IRP_MN_WRITE_CONFIG_STRING;
			break;
		case IRP_MN_EJECT:
			irpMinorString = IRP_MN_EJECT_STRING;
			break;
		case IRP_MN_SET_LOCK:
			irpMinorString = IRP_MN_SET_LOCK_STRING;
			break;
		case IRP_MN_QUERY_ID:
			irpMinorString = IRP_MN_QUERY_ID_STRING;
			break;
		case IRP_MN_QUERY_PNP_DEVICE_STATE:
			irpMinorString = IRP_MN_QUERY_PNP_DEVICE_STATE_STRING;
			break;
		case IRP_MN_QUERY_BUS_INFORMATION:
			irpMinorString = IRP_MN_QUERY_BUS_INFORMATION_STRING;
			break;
		case IRP_MN_DEVICE_USAGE_NOTIFICATION:
			irpMinorString = IRP_MN_DEVICE_USAGE_NOTIFICATION_STRING;
			break;
		case IRP_MN_SURPRISE_REMOVAL:
			irpMinorString = IRP_MN_SURPRISE_REMOVAL_STRING;
			break;
		case IRP_MN_QUERY_LEGACY_BUS_INFORMATION:
			irpMinorString = IRP_MN_QUERY_LEGACY_BUS_INFORMATION_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp minor code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;


	case IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION:
		irpMajorString = IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION_STRING;
		break;

	case IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION:
		irpMajorString = IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION_STRING;
		break;

	case IRP_MJ_ACQUIRE_FOR_MOD_WRITE:
		irpMajorString = IRP_MJ_ACQUIRE_FOR_MOD_WRITE_STRING;
		break;

	case IRP_MJ_RELEASE_FOR_MOD_WRITE:
		irpMajorString = IRP_MJ_RELEASE_FOR_MOD_WRITE_STRING;
		break;

	case IRP_MJ_ACQUIRE_FOR_CC_FLUSH:
		irpMajorString = IRP_MJ_ACQUIRE_FOR_CC_FLUSH_STRING;
		break;

	case IRP_MJ_RELEASE_FOR_CC_FLUSH:
		irpMajorString = IRP_MJ_RELEASE_FOR_CC_FLUSH_STRING;
		break;

	case IRP_MJ_NOTIFY_STREAM_FO_CREATION:
		irpMajorString = IRP_MJ_NOTIFY_STREAM_FO_CREATION_STRING;
		break;



	case IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE:
		irpMajorString = IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE_STRING;
		break;

	case IRP_MJ_NETWORK_QUERY_OPEN:
		irpMajorString = IRP_MJ_NETWORK_QUERY_OPEN_STRING;
		break;

	case IRP_MJ_MDL_READ:
		irpMajorString = IRP_MJ_MDL_READ_STRING;
		break;

	case IRP_MJ_MDL_READ_COMPLETE:
		irpMajorString = IRP_MJ_MDL_READ_COMPLETE_STRING;
		break;

	case IRP_MJ_PREPARE_MDL_WRITE:
		irpMajorString = IRP_MJ_PREPARE_MDL_WRITE_STRING;
		break;

	case IRP_MJ_MDL_WRITE_COMPLETE:
		irpMajorString = IRP_MJ_MDL_WRITE_COMPLETE_STRING;
		break;

	case IRP_MJ_VOLUME_MOUNT:
		irpMajorString = IRP_MJ_VOLUME_MOUNT_STRING;
		break;

	case IRP_MJ_VOLUME_DISMOUNT:
		irpMajorString = IRP_MJ_VOLUME_DISMOUNT_STRING;
		break;

	case IRP_MJ_TRANSACTION_NOTIFY:
		irpMajorString = IRP_MJ_TRANSACTION_NOTIFY_STRING;
		switch (MinorCode) {
		case 0:
			irpMinorString = TRANSACTION_BEGIN;
			break;
		case TRANSACTION_NOTIFY_PREPREPARE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_PREPREPARE_STRING;
			break;
		case TRANSACTION_NOTIFY_PREPARE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_PREPARE_STRING;
			break;
		case TRANSACTION_NOTIFY_COMMIT_CODE:
			irpMinorString = TRANSACTION_NOTIFY_COMMIT_STRING;
			break;
		case TRANSACTION_NOTIFY_COMMIT_FINALIZE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_COMMIT_FINALIZE_STRING;
			break;
		case TRANSACTION_NOTIFY_ROLLBACK_CODE:
			irpMinorString = TRANSACTION_NOTIFY_ROLLBACK_STRING;
			break;
		case TRANSACTION_NOTIFY_PREPREPARE_COMPLETE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_PREPREPARE_COMPLETE_STRING;
			break;
		case TRANSACTION_NOTIFY_PREPARE_COMPLETE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_COMMIT_COMPLETE_STRING;
			break;
		case TRANSACTION_NOTIFY_ROLLBACK_COMPLETE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_ROLLBACK_COMPLETE_STRING;
			break;
		case TRANSACTION_NOTIFY_RECOVER_CODE:
			irpMinorString = TRANSACTION_NOTIFY_RECOVER_STRING;
			break;
		case TRANSACTION_NOTIFY_SINGLE_PHASE_COMMIT_CODE:
			irpMinorString = TRANSACTION_NOTIFY_SINGLE_PHASE_COMMIT_STRING;
			break;
		case TRANSACTION_NOTIFY_DELEGATE_COMMIT_CODE:
			irpMinorString = TRANSACTION_NOTIFY_DELEGATE_COMMIT_STRING;
			break;
		case TRANSACTION_NOTIFY_RECOVER_QUERY_CODE:
			irpMinorString = TRANSACTION_NOTIFY_RECOVER_QUERY_STRING;
			break;
		case TRANSACTION_NOTIFY_ENLIST_PREPREPARE_CODE:
			irpMinorString = TRANSACTION_NOTIFY_ENLIST_PREPREPARE_STRING;
			break;
		case TRANSACTION_NOTIFY_LAST_RECOVER_CODE:
			irpMinorString = TRANSACTION_NOTIFY_LAST_RECOVER_STRING;
			break;
		case TRANSACTION_NOTIFY_INDOUBT_CODE:
			irpMinorString = TRANSACTION_NOTIFY_INDOUBT_STRING;
			break;
		case TRANSACTION_NOTIFY_PROPAGATE_PULL_CODE:
			irpMinorString = TRANSACTION_NOTIFY_PROPAGATE_PULL_STRING;
			break;
		case TRANSACTION_NOTIFY_PROPAGATE_PUSH_CODE:
			irpMinorString = TRANSACTION_NOTIFY_PROPAGATE_PUSH_STRING;
			break;
		case TRANSACTION_NOTIFY_MARSHAL_CODE:
			irpMinorString = TRANSACTION_NOTIFY_MARSHAL_STRING;
			break;
		case TRANSACTION_NOTIFY_ENLIST_MASK_CODE:
			irpMinorString = TRANSACTION_NOTIFY_ENLIST_MASK_STRING;
			break;
		default:
			sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Transaction notication code (%u)", MinorCode);
			irpMinorString = errorBuf;
		}
		break;


	default:
		sprintf_s(errorBuf, sizeof(errorBuf), "Unknown Irp major function (%d)", MajorCode);
		irpMajorString = errorBuf;
		break;
	}

	if (OutputFile) {

		if (irpMinorString) {

			fprintf(OutputFile, "\t%-35s\t%-35s", irpMajorString, irpMinorString);

		}
		else {

			fprintf(OutputFile, "\t%-35s\t                                   ", irpMajorString);
		}

	}
	else {

		if (PrintMajorCode) {

			printf("%-35s ", irpMajorString);

		}
		else {

			if (irpMinorString) {

				printf("                                                                     %-35s\n",
					irpMinorString);
			}
		}
	}
}

/*++
Routine Description:

Formats the values in a SystemTime struct into the buffer
passed in.  The resulting string is NULL terminated.  The format
for the time is:
hours:minutes:seconds:milliseconds

Arguments:

SystemTime - the struct to format
Buffer - the buffer to place the formatted time in
BufferLength - the size of the buffer

Return Value:

The length of the string returned in Buffer.

--*/
ULONG FormatSystemTime(_In_ SYSTEMTIME *SystemTime, _Out_writes_bytes_(BufferLength) CHAR *Buffer, _In_ ULONG BufferLength)
{
	ULONG returnLength = 0;

	if (BufferLength < TIME_BUFFER_LENGTH) {

		//
		// Buffer is too short so exit
		//

		return 0;
	}

	returnLength = sprintf_s(Buffer,
		BufferLength,
		"%02d:%02d:%02d:%03d",
		SystemTime->wHour,
		SystemTime->wMinute,
		SystemTime->wSecond,
		SystemTime->wMilliseconds);

	return returnLength;
}

/*++
Routine Description:

Prints a Data log record to the specified file.  The output is in a tab
delimited format with the fields in the following order:

SequenceNumber, OriginatingTime, CompletionTime, CallbackMajorId, CallbackMinorId,
Flags, NoCache, Paging I/O, Synchronous, Synchronous paging, FileName,
ReturnStatus, FileName


Arguments:

SequenceNumber - the sequence number for this log record
Name - the name of the file that this Irp relates to
RecordData - the Data record to print
File - the file to print to

Return Value:

None.

--*/
VOID FileDump(_In_ ULONG SequenceNumber, _In_ WCHAR CONST *Name, _In_ PRECORD_DATA RecordData, _In_ FILE *File)
{
	FILETIME localTime;
	SYSTEMTIME systemTime;
	CHAR time[TIME_BUFFER_LENGTH];
	static BOOLEAN didFileHeader = FALSE;

	//
	// Is this an Irp or a FastIo?
	//

	if (!didFileHeader) {

#if defined(_WIN64)
		fprintf(File, "Opr\t  SeqNum  \t PreOp Time \tPostOp Time \t Process.Thrd\t          Major Operation          \t          Minor Operation          \t   IrpFlags    \t      DevObj      \t     FileObj      \t    Transactn     \t    status:inform            \t      Arg 1       \t      Arg 2       \t      Arg 3       \t      Arg 4       \t      Arg 5       \t  Arg 6   \tName\n");
		fprintf(File, "---\t----------\t------------\t------------\t-------------\t-----------------------------------\t-----------------------------------\t---------------\t------------------\t------------------\t------------------\t-----------------------------\t------------------\t------------------\t------------------\t------------------\t------------------\t----------\t--------------------------------------------------\n");
#else
		fprintf(File, "Opr\t  SeqNum  \t PreOp Time \tPostOp Time \t Process.Thrd\t          Major Operation          \t          Minor Operation          \t   IrpFlags    \t  DevObj  \t FileObj  \tTransactn \t    status:inform    \t  Arg 1   \t  Arg 2   \t  Arg 3   \t  Arg 4   \t  Arg 5   \t  Arg 6   \tName\n");
		fprintf(File, "---\t----------\t------------\t------------\t-------------\t-----------------------------------\t-----------------------------------\t---------------\t----------\t----------\t----------\t---------------------\t----------\t----------\t----------\t----------\t----------\t----------\t--------------------------------------------------\n");
#endif
		didFileHeader = TRUE;
	}

	//
	// Is this an Irp or a FastIo?
	//

	if (RecordData->Flags & FLT_CALLBACK_DATA_IRP_OPERATION) {

		fprintf(File, "IRP");

	}
	else if (RecordData->Flags & FLT_CALLBACK_DATA_FAST_IO_OPERATION) {

		fprintf(File, "FIO");

	}
	else if (RecordData->Flags & FLT_CALLBACK_DATA_FS_FILTER_OPERATION) {

		fprintf(File, "FSF");

	}
	else {

		fprintf(File, "ERR");
	}

	//
	//  Print the sequence number
	//

	fprintf(File, "\t0x%08X", SequenceNumber);

	//
	// Convert originating time
	//

	FileTimeToLocalFileTime((FILETIME *)&(RecordData->OriginatingTime),
		&localTime);
	FileTimeToSystemTime(&localTime,
		&systemTime);

	if (FormatSystemTime(&systemTime, time, TIME_BUFFER_LENGTH)) {

		fprintf(File, "\t%-12s", time);

	}
	else {

		fprintf(File, "\t%-12s", TIME_ERROR);
	}

	//
	// Convert completion time
	//

	FileTimeToLocalFileTime((FILETIME *)&(RecordData->CompletionTime),
		&localTime);
	FileTimeToSystemTime(&localTime,
		&systemTime);

	if (FormatSystemTime(&systemTime, time, TIME_BUFFER_LENGTH)) {

		fprintf(File, "\t%-12s", time);

	}
	else {

		fprintf(File, "\t%-12s", TIME_ERROR);
	}

	fprintf(File, "\t%8llx.%-4llx ", RecordData->ProcessId, RecordData->ThreadId);

	PrintIrpCode(RecordData->CallbackMajorId,
		RecordData->CallbackMinorId,
		File,
		TRUE);

	//
	// Interpret set IrpFlags
	//

	fprintf(File, "\t0x%08lx ", RecordData->IrpFlags);
	fprintf(File, "%s", (RecordData->IrpFlags & IRP_NOCACHE) ? "N" : "-");
	fprintf(File, "%s", (RecordData->IrpFlags & IRP_PAGING_IO) ? "P" : "-");
	fprintf(File, "%s", (RecordData->IrpFlags & IRP_SYNCHRONOUS_API) ? "S" : "-");
	fprintf(File, "%s", (RecordData->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) ? "Y" : "-");

	fprintf(File, "\t0x%08p", (PVOID)RecordData->DeviceObject);
	fprintf(File, "\t0x%08p", (PVOID)RecordData->FileObject);
	fprintf(File, "\t0x%08p", (PVOID)RecordData->Transaction);
	fprintf(File, "\t0x%08lx:0x%p", RecordData->Status, (PVOID)RecordData->Information);

	fprintf(File, "\t0x%p", RecordData->Arg1);
	fprintf(File, "\t0x%p", RecordData->Arg2);
	fprintf(File, "\t0x%p", RecordData->Arg3);
	fprintf(File, "\t0x%p", RecordData->Arg4);
	fprintf(File, "\t0x%p", RecordData->Arg5);
	fprintf(File, "\t0x%08I64x", RecordData->Arg6.QuadPart);

	fprintf(File, "\t%S", Name);
	fprintf(File, "\n");
}

/*++
Routine Description:

Prints a Irp log record to the screen in the following order:
SequenceNumber, OriginatingTime, CompletionTime, IrpMajor, IrpMinor,
Flags, IrpFlags, NoCache, Paging I/O, Synchronous, Synchronous paging,
FileName, ReturnStatus, FileName

Arguments:

SequenceNumber - the sequence number for this log record
Name - the file name to which this Irp relates
RecordData - the Irp record to print

Return Value:

None.

--*/
VOID ScreenDump(_In_ ULONG SequenceNumber, _In_ WCHAR CONST *Name, _In_ PRECORD_DATA RecordData)
{
	FILETIME localTime;
	SYSTEMTIME systemTime;
	CHAR time[TIME_BUFFER_LENGTH];
	static BOOLEAN didScreenHeader = FALSE;

	//
	// Is this an Irp or a FastIo?
	//

	if (!didScreenHeader) {

#if defined(_WIN64)
		printf("Opr  SeqNum   PreOp Time  PostOp Time   Process.Thrd      Major/Minor Operation          IrpFlags          DevObj           FileObj          Transact       status:inform                               Arguments                                                                             Name\n");
		printf("--- -------- ------------ ------------ ------------- ----------------------------------- ------------- ---------------- ---------------- ---------------- ------------------------- --------------------------------------------------------------------------------------------------------- -----------------------------------\n");
#else
		printf("Opr  SeqNum   PreOp Time  PostOp Time   Process.Thrd      Major/Minor Operation          IrpFlags      DevObj   FileObj  Transact   status:inform                               Arguments                             Name\n");
		printf("--- -------- ------------ ------------ ------------- ----------------------------------- ------------- -------- -------- -------- ----------------- ----------------------------------------------------------------- -----------------------------------\n");
#endif
		didScreenHeader = TRUE;
	}

	//
	//  Display informatoin
	//

	if (RecordData->Flags & FLT_CALLBACK_DATA_IRP_OPERATION) {

		printf("IRP ");

	}
	else if (RecordData->Flags & FLT_CALLBACK_DATA_FAST_IO_OPERATION) {

		printf("FIO ");

	}
	else if (RecordData->Flags & FLT_CALLBACK_DATA_FS_FILTER_OPERATION) {

		printf("FSF ");
	}
	else {

		printf("ERR ");
	}

	printf("%08X ", SequenceNumber);


	//
	// Convert originating time
	//

	FileTimeToLocalFileTime((FILETIME *)&(RecordData->OriginatingTime),
		&localTime);
	FileTimeToSystemTime(&localTime,
		&systemTime);

	if (FormatSystemTime(&systemTime, time, TIME_BUFFER_LENGTH)) {

		printf("%-12s ", time);

	}
	else {

		printf("%-12s ", TIME_ERROR);
	}

	//
	// Convert completion time
	//

	FileTimeToLocalFileTime((FILETIME *)&(RecordData->CompletionTime),
		&localTime);
	FileTimeToSystemTime(&localTime,
		&systemTime);

	if (FormatSystemTime(&systemTime, time, TIME_BUFFER_LENGTH)) {

		printf("%-12s ", time);

	}
	else {

		printf("%-12s ", TIME_ERROR);
	}

	printf("%8llx.%-4llx ", RecordData->ProcessId, RecordData->ThreadId);

	PrintIrpCode(RecordData->CallbackMajorId,
		RecordData->CallbackMinorId,
		NULL,
		TRUE);

	//
	// Interpret set IrpFlags
	//

	printf("%08lx ", RecordData->IrpFlags);
	printf("%s", (RecordData->IrpFlags & IRP_NOCACHE) ? "N" : "-");
	printf("%s", (RecordData->IrpFlags & IRP_PAGING_IO) ? "P" : "-");
	printf("%s", (RecordData->IrpFlags & IRP_SYNCHRONOUS_API) ? "S" : "-");
	printf("%s ", (RecordData->IrpFlags & IRP_SYNCHRONOUS_PAGING_IO) ? "Y" : "-");

	printf("%08p ", (PVOID)RecordData->DeviceObject);
	printf("%08p ", (PVOID)RecordData->FileObject);
	printf("%08p ", (PVOID)RecordData->Transaction);
	printf("%08lx:%p ", RecordData->Status, (PVOID)RecordData->Information);

	printf("1:%p 2:%p 3:%p 4:%p 5:%p 6:%08I64x ",
		RecordData->Arg1,
		RecordData->Arg2,
		RecordData->Arg3,
		RecordData->Arg4,
		RecordData->Arg5,
		RecordData->Arg6.QuadPart);

	printf("%S", Name);
	printf("\n");
	PrintIrpCode(RecordData->CallbackMajorId,
		RecordData->CallbackMinorId,
		NULL,
		FALSE);
}

// 
// TrackProcess
// Designed to track a process in the ProcessMap hash map.
// @variable ProcessMap - UTHashMap to track the process in
// @variable ProcessID - Process ID
// @variable ThreatLevel - Set the initial threat of a process
// @variable whitelistedCategory - Set the level of whitelisting
//
int TrackProcess(struct ProcessThreatLevel ** ProcessMap, FILE_ID ProcessId, int ThreatLevel, int whitelistedCategory)
{
	struct ProcessThreatLevel * tmpProcess = NULL;
	// UNTRACKED indicates that we know the process does not exist in the map
	if (whitelistedCategory != UNTRACKED)
		HASH_FIND_INT(*ProcessMap, &ProcessId, tmpProcess);
	if (tmpProcess == NULL || whitelistedCategory == UNTRACKED)
	{
		// Will add if not found
		tmpProcess = malloc(sizeof(struct ProcessThreatLevel));
		tmpProcess->dwProcessId = ProcessId;
		tmpProcess->dwThreatLevel = ThreatLevel;
		tmpProcess->dwIsWhiteListed = whitelistedCategory;
		HASH_ADD_INT(*ProcessMap, dwProcessId, tmpProcess);
		return SUCCESS;
	}

	// Return failure if process already in map
	return FAILURE;
}

// 
// FindProcess
// Attempts to find a process in the process map
// @variable ProcessMap - UTHashMap that contains processes
// @variable ProcessID - Process ID
//
struct ProcessThreatLevel * FindProcess(struct ProcessThreatLevel * ProcessMap, FILE_ID ProcessId)
{
	struct ProcessThreatLevel * ptl;
	HASH_FIND_INT(ProcessMap, &ProcessId, ptl);
	return ptl;
}

// 
// UntrackProcess
// Removes a process from being tracked in the process map
// @variable ProcessMap - UTHashMap that contains processes
// @variable ProcessID - Process ID
//

int UntrackProcess(struct ProcessThreatLevel ** ProcessMap, FILE_ID ProcessId)
{
	struct ProcessThreatLevel * tmpProcess = NULL;

	// Find Process
	HASH_FIND_INT(*ProcessMap, &ProcessId, tmpProcess);
	if (tmpProcess != NULL)
	{
		// Remove process from map and free data
		HASH_DEL(*ProcessMap, tmpProcess);
		free(tmpProcess);
		return SUCCESS;
	}

	// Return failure if process not found in map
	return FAILURE;
}

// 
// IsWhitelisted
// Returns the whitelisted status of a process
// @variable ProcessMap - UTHashMap that contains processes
// @variable ProcessID - Process ID
//
int IsWhiteListed(struct ProcessThreatLevel * ProcessMap, FILE_ID ProcessId)
{
	struct ProcessThreatLevel * tPointer = NULL;

	//find the process
	HASH_FIND_INT(ProcessMap, &ProcessId, tPointer);

	if (tPointer == NULL) {
		// ProcessId is not tracked
		return UNTRACKED;
	}

	return tPointer->dwIsWhiteListed;
}

// 
// IncreaseThreatLevel
// Increments a processes threat level
// @variable ProcessMap - UTHashMap that contains processes
// @variable ProcessID - Process ID
// @variable ThreatIncrease - Amount of threat to increase the threatlevel by
//
int IncreaseThreatLevel(struct ProcessThreatLevel ** ProcessMap, FILE_ID ProcessId, int ThreatIncrease) {
	struct ProcessThreatLevel * tPointer;
	//find the process
	HASH_FIND_INT(*ProcessMap, &ProcessId, tPointer);

	//use the pointer to change the value of the Threat
	tPointer->dwThreatLevel = tPointer->dwThreatLevel + ThreatIncrease;

	//return the threatlevel for threshold checking
	return tPointer->dwThreatLevel;

}

// 
// TrackHeuristic
// Adds a heuristic path to the passed HeuristicMap
// @variable HeuristicMap - UTHashmap that contains heuristics
// @variable wHeuristicPath - heuristic path
// @variable dwThreatLevel - Amount of threat associated with path
//
int TrackHeuristic(struct HeuristicSignature ** HeuristicMap, WCHAR CONST * wHeuristicPath, DWORD dwThreatLevel)
{
	struct HeuristicSignature * tmpHeuristic = NULL;

	// Determines if hash is already in map
	__pragma(warning(push))
		__pragma(warning(disable:4047))
		__pragma(warning(disable:4024))
		HASH_FIND_STR(*HeuristicMap, &wHeuristicPath, tmpHeuristic);
	__pragma(warning(pop))
		if (tmpHeuristic == NULL)
		{
			// Will add if not found
			tmpHeuristic = malloc(sizeof(struct HeuristicSignature));
			tmpHeuristic->wHeuristicPath = wHeuristicPath;
			tmpHeuristic->dwThreatLevel = dwThreatLevel;
		
			HASH_ADD_STR(*HeuristicMap, wHeuristicPath, tmpHeuristic);
			return SUCCESS;
		}

	// Return failure if process already in map
	return FAILURE;
}

// 
// FindHeuristic
// Finds a heuristic in a HeuristicMap
// @variable HeuristicMap - UTHashmap that contains heuristics
// @variable wHeuristicPath - heuristic path
//
struct HeuristicSignature * FindHeuristic(struct HeuristicSignature * HeuristicMap, WCHAR CONST * wHeuristicPath)
{
	struct HeuristicSignature * hs = NULL;
	struct HeuristicSignature * tmp = NULL;

	for (tmp = HeuristicMap; tmp != NULL; tmp = tmp->hh.next)
	{
		if (!(wcscmp(wHeuristicPath, tmp->wHeuristicPath))) {
	
			return tmp;
		}
	}
	return hs;
}

// 
// UntrackHeuristic
// Removes a heuristic from a HeuristicMap
// @variable HeuristicMap - UTHashmap that contains heuristics
// @variable wHeuristicPath - heuristic path
//
int UntrackHeuristic(struct HeuristicSignature ** HeuristicMap, WCHAR CONST * wHeuristicPath)
{
	struct HeuristicSignature * tmpHeuristic = NULL;

	// Find Process
	__pragma(warning(push))
		__pragma(warning(disable:4047))
		__pragma(warning(disable:4024))
		HASH_FIND_STR(*HeuristicMap, &wHeuristicPath, tmpHeuristic);
	__pragma(warning(pop))
		if (tmpHeuristic != NULL)
		{
			// Remove process from map and free data
			HASH_DEL(*HeuristicMap, tmpHeuristic);
			free(tmpHeuristic);
			return SUCCESS;
		}

	// Return failure if process not found in map
	return FAILURE;
}

// 
// PrintHeuristics
// Prints all the tracked heuristics in a heuristicmap
//
void PrintHeuristics(struct HeuristicSignature * HeuristicMap) {
	struct HeuristicSignature * tmp;
	printf("\n"
		"    Signature\t\t\t\t\t\t\t\t\tThreat Level\n"
		"    --------------------------------------------------------------------------  ------------\n"
	);
	for (tmp = HeuristicMap; tmp != NULL; tmp = tmp->hh.next)
	{
		printf("    %-74ls  %-14d\n", tmp->wHeuristicPath, tmp->dwThreatLevel);
	}
}

// 
// PrintWhitelist
// Prints all the tracked processes in a ProcessMap
//
void PrintWhiteList(struct ProcessTheatLevel * ProcessMap) {
	struct ProcessThreatLevel * tmp;
	printf("\n"
		"    Whitelisted Process                               Category     \n"
		"    ---------------------------------------------------------------\n"
	);
	for (tmp = ProcessMap; tmp != NULL; tmp = tmp->hh.next)
	{
		if (tmp->dwIsWhiteListed > 0) {
			printf("    %lld | %d\n", tmp->dwProcessId, tmp->dwIsWhiteListed);
		}
	}
}

// 
// KillProcess
// Attempts to kill the process that is passed to it
//
void KillProcess(FILE_ID ProcessId) {
	char buf[25];
	sprintf(buf, "taskkill /pid %lld /f /t", ProcessId);
	system(buf);
}

//
// GetPIDFromName
// Returns a process ID associated with the name of a process
//
int * GetPIDFromName(const WCHAR * ProcessName)
{
	// The pragma are to disable the compiler warnings for incorrect types passed to
	//		CreateToolhelp32Snapshot. The variables passed are MSDN documented,
	//		And there's no other way to do it.
	__pragma(warning(push))
		__pragma(warning(disable:4047))
		__pragma(warning(disable:4024))
		HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	__pragma(warning(pop))
		PROCESSENTRY32 pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);
	static int ProcessIds[10];
	int counter = 0;
	while (hRes)
	{
		if (!(wcscmp(pEntry.szExeFile, ProcessName)))
		{
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0,
				(DWORD)pEntry.th32ProcessID);
			if (hProcess != NULL)
			{
				CloseHandle(hProcess);
				ProcessIds[counter] = pEntry.th32ProcessID;
				counter++;
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
	return ProcessIds;
}

//
// GetFileNameFromPID
// Returns the path associated with a PID
//
void GetFileNameFromPID(DWORD dwProcessId, TCHAR * path)
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;
	unsigned int i;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, dwProcessId);

	if (hProcess != NULL)
	{
		if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
		{
			for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
			{
				TCHAR szModPathName[MAX_PATH];
				// Get the full path to the module's file.
				if (GetModuleFileNameEx(hProcess, hMods[i], szModPathName, sizeof(szModPathName)))
				{
					wcscpy(path, szModPathName);
					break;
				}
			}
		}
	}
	CloseHandle(hProcess);
}

//
// VerifyPESignature
// Verifies the digital signature of a file
//
BOOL VerifyPESignature(LPCWSTR pwszSourceFile)
{
	LONG lStatus;
	DWORD dwLastError;
	BOOL verified = FALSE;
	TCHAR minispyPath[MAX_PATH];

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

	// Returning true if Minispy
	GetFileNameFromPID(GetCurrentProcessId(), &minispyPath);
	if (!(wcscmp(minispyPath, pwszSourceFile))) {
		return TRUE;
	}

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
		if (IsVerbose || IsVeryVerbose)
			wprintf_s(L"The file \"%s\" is signed and the signature "
				L"was verified.\n",
				pwszSourceFile);
		verified = TRUE;
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
			if (IsVerbose || IsVeryVerbose)
				wprintf_s(L"The file \"%s\" is not signed.\n",
					pwszSourceFile);
		}
		else
		{
			// The signature was not valid or there was an error 
			// opening the file.
			if (IsVerbose || IsVeryVerbose)
				wprintf_s(L"An unknown error occurred trying to "
					L"verify the signature of the \"%s\" file.\n",
					pwszSourceFile);
		}

		break;

	case TRUST_E_EXPLICIT_DISTRUST:
		// The hash that represents the subject or the publisher 
		// is not allowed by the admin or user.
		if (IsVerbose || IsVeryVerbose)
			wprintf_s(L"The signature is present, but specifically "
				L"disallowed.\n");
		break;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		// The user clicked "No" when asked to install and run.
		if (IsVerbose || IsVeryVerbose)
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
		if (IsVerbose || IsVeryVerbose)
			wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
				L"representing the subject or the publisher wasn't "
				L"explicitly trusted by the admin and admin policy "
				L"has disabled user trust. No signature, publisher "
				L"or timestamp errors.\n");
		break;
	case TRUST_E_SELF_SIGNED_SIGNATURE:
		if (IsVerbose || IsVeryVerbose)
			wprintf_s(L"The file \"%s\" is self signed.\n",
				pwszSourceFile);
		break;
	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. lStatus contains the 
		// publisher or time stamp chain error.
		if (IsVerbose || IsVeryVerbose)
			wprintf_s(L"File \"%s\" produced error: 0x%x.\n",
				pwszSourceFile,
				lStatus);
		break;
	}

	// Any hWVTStateData must be released by a call with close.
	WinTrustData.dwStateAction = WTD_STATEACTION_CLOSE;

	lStatus = WinVerifyTrust(
		NULL,
		&WVTPolicyGUID,
		&WinTrustData);

	// Overrides signature detection for DLLHOST.exe to avoid false positives
	// if signature detection fails
	if (wcsicmp(pwszSourceFile, L"C:\\Windows\\System32\\dllhost.exe") == 0 || wcsicmp(pwszSourceFile, L"C:\\Windows\\SysWOW64\\dllhost.exe") == 0) {
		verified = TRUE;
	}

	return verified;
}

// Check the status of the current queue specfied and remove all timestamp 
// entries for the specfic PID, that are over a minute old
void CleanUpQueue(struct PidChangeTracker *pTracker) {

	int i;
	time_t now;
	struct tm *t;

	// Checks to see if the timestamp at front of the queue is older
	// then a minute, and if not the loops breaks since the most recent
	// timestamps are at the back of the queue
	time(&now);
	if (pTracker->size > 0) {
		for (i = 0; i < pTracker->size; i++) {
			t = (struct tm*)utarray_front(pTracker->queue);
			if (difftime(now, mktime(t)) >= 30) {
				utarray_erase(pTracker->queue, 0, 1);
			}
			else {
				break;
			}
		}
	}

	// Updates the size of the queue and the amount of checks
	// made against the queue
	pTracker->size = utarray_len(pTracker->queue);

	// Calculating the average writes per second for a particular PID
	// If checks are zero, we set the writes per second to the size of pTracker
	// to avoid division by 0
	if (pTracker->checks == 0) {
		pTracker->writesPerSec = (float)pTracker->size;
	}
	else {
		if (pTracker->checks < 30) {
			pTracker->writesPerSec = (float)pTracker->size / (float)pTracker->checks;
		}
		else {
			pTracker->writesPerSec = (float)pTracker->size / 30.0f;
		}
	}

	pTracker->checks++;
}

// Resets all the fields for a particular PID for Temproral Activity Tracking, if process killed
int ClearPIDInfo(Array *qBucket, int parent) {
	int x = 0;
	int y = 0;

	for (x = 0; x < qBucket->used; x++) {
		// Checks to see if PID already exists in one of the queues
		if (qBucket->array[x].pid == parent) {

			// Clears the timestamps for the particular parent (PID) in Temporal-Activity Tracking queue bucket
			for (y = 0; y < qBucket->array[x].size; y++) {
				utarray_erase(qBucket->array[x].queue, 0, 1);
			}
			
			// Resets all its properties to zero, when PID is killed, that way if a new process spawns with the same PID,
			// it does not inherit all the properties of the previous process
			qBucket->array[x].size = 0;
			qBucket->array[x].checks = 0;
			qBucket->array[x].writesPerSec = 0;
			qBucket->array[x].isHigh = 0;
			qBucket->array[x].isMedium = 0;
			qBucket->array[x].isLow = 0;
			break;
		}
	}

	return 1;
}

//
// IsProcessDead
// Loops through all active processes looking for a PID that is passed
// Additional notes:
//		If a process is dead but has children microsoft will keep that PID
//		from being reused.
//
int isProcessDead(FILE_ID pid) {
	// Variables
	HANDLE hProcess;
	DWORD exitCode;

	// Determine if process is dead
	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
	if (hProcess == NULL) {
		return TRUE;
	}
	GetExitCodeProcess(hProcess, &exitCode);
	if (exitCode == STILL_ACTIVE) {
		return FALSE;
	}
	else {
		return TRUE;
	}
}


//
// Enables Debug Privileges
//		By enableing the SE_DEBUG_FUNCTION privilege we can use the OpenProcess function and obtain
//		a handle for any process alive on the system (excluding porcessess 0 and 4)
//
int EnableDebugPrivileges()
{
	// 
	HANDLE hProcToken = 0;
	// Token privileges structure
	TOKEN_PRIVILEGES tkpPriv = { 0 };

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hProcToken))
	{
		return 1;
	}

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkpPriv.Privileges[0].Luid);

	// Count of privilege
	tkpPriv.PrivilegeCount = 1;

	// Set up "enable" attribute for privilege
	tkpPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Set up privilege
	AdjustTokenPrivileges(hProcToken, FALSE, &tkpPriv, 0, 0, 0);

	CloseHandle(hProcToken);

	return 0;
}