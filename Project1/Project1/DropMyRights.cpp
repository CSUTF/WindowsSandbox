#include "stdafx.h"
#include <stdio.h>
#include <windows.h>
#include <windowsx.h>
#include <sddl.h>
#include <shlobj.h>
#include "Resource.h"
#include <iostream>

#define APPLICATION L"DropMyRights"
#define VERSION		L"v1.04"
#define AUTHOR		L"Michael Howard (mikehow@microsoft.com)"
using namespace std;


//////////////////////////////////////////////////////////////////////////////////
void Usage() {
	wchar_t *wszUsage =
		L"\n\n"
		APPLICATION L" " VERSION L" by " AUTHOR L"\n"
		L"Usage is:\n\n"
		L"\t" APPLICATION L" {path} [N|C|U]\n\n"
		L"Where: \n"
		L"\tpath is the full path to an executable to run.\n"
		L"\tN = run as normal user (default).\n"
		L"\tC = run as constrained user."
		L"\tU = run as an untrusted user.\n";

	fwprintf(stderr, wszUsage);
}

//////////////////////////////////////////////////////////////////////////////////
DWORD wmain(int argc, wchar_t **argv) {

	DWORD fStatus = ERROR_SUCCESS;

	if (2 != argc && 3 != argc) {
		Usage();
		return ERROR_INVALID_PARAMETER;
	}

	// get the SAFER level
	DWORD hSaferLevel = SAFER_LEVELID_NORMALUSER;
	if (3 == argc && argv[2]) {
		switch (argv[2][0]) {
		case 'C':
		case 'c':  hSaferLevel = SAFER_LEVELID_CONSTRAINED;
			break;
		case 'U':
		case 'u':	hSaferLevel = SAFER_LEVELID_UNTRUSTED;
			break;

		default:	hSaferLevel = SAFER_LEVELID_NORMALUSER;
			break;
		}
	}

	// get the command line, and make sure it's not bogus
	wchar_t *wszPath = argv[1];
	size_t cchLen = 0;
	if (FAILED(StringCchLength(wszPath, MAX_PATH, &cchLen)))
		return ERROR_INVALID_PARAMETER;

	SAFER_LEVEL_HANDLE hAuthzLevel = NULL;
	if (SaferCreateLevel(SAFER_SCOPEID_USER,
		hSaferLevel,
		0,
		&hAuthzLevel, NULL)) {

		// Create a job kernel object
		HANDLE hjob = CreateJobObject(NULL, NULL);

		// Place some restrictions on processes in the job

		// First, set some basic restrictions
		JOBOBJECT_BASIC_LIMIT_INFORMATION jobli = { 0 };

		// The process always runs in the idle priority class
		jobli.PriorityClass = IDLE_PRIORITY_CLASS;

		// The job cannot use more than 1 second of CPU time
		// 1 second in 100-ns intervals
		jobli.PerJobUserTimeLimit.QuadPart = 1000000;

		// These are the only 2 restrictions I want placed on the job (process)
		jobli.LimitFlags = JOB_OBJECT_LIMIT_PRIORITY_CLASS |
			JOB_OBJECT_LIMIT_JOB_TIME;
		SetInformationJobObject(hjob, JobObjectBasicLimitInformation, &jobli, sizeof(jobli));
		
		/*******************File Mapping*****************************/ 
		TCHAR szCurDir[MAX_PATH];

		DWORD cchLength = GetFullPathName(TEXT("C:"), MAX_PATH, szCurDir, NULL); 
		
		
		TCHAR location[] = TEXT("C:\\Users\\DAnnTheMann\\Desktop\\DropMyRights\\DropMyRights\\k.txt");
		TCHAR mapName[] = TEXT("SharedFile");
		HANDLE file = CreateFile(location,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_READONLY,NULL);//File handle
		HANDLE hMapFile = CreateFileMapping(
			INVALID_HANDLE_VALUE, // use Paging File
			NULL, //Defaut Security
			PAGE_READONLY,//ReadOnly
			0,//Maximum Objext Size
			256,//..
			mapName);//Name of Mapping Object
		if (hMapFile == NULL)
		{
			
			printf("Error With FileMapping\n");
			return 1;
		}


		/********************************************/

		// Spawn the process that is to be in the job
		// Note: You must first spawn the process and then place the process in the
		// job.
		// This means that the process's thread must be initially suspended so that
		// it can't execute any code outside of the job's restrictions.
		STARTUPINFO si;
		ZeroMemory(&si, sizeof(STARTUPINFO));
		si.cb = sizeof(STARTUPINFO);
		si.lpDesktop = NULL;//Alt to Alternative Desktop But not as Secure
		PROCESS_INFORMATION pi;

		//  Generate the restricted token that we will use.
		HANDLE hToken = NULL;

		HANDLE hNewToken = NULL;
		SID_IDENTIFIER_AUTHORITY MLAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
		PSID pIntegritySid = NULL;
		TOKEN_MANDATORY_LABEL tml = { 0 };

		OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY, &hToken);



		if (SaferComputeTokenFromLevel(
			hAuthzLevel,    // SAFER Level handle
			hToken,           // NULL is current thread token.
			&hNewToken,        // Target token
			0,              // No flags
			NULL)) {        // Reserved

			//STARTUPINFO si;
			//ZeroMemory(&si, sizeof(STARTUPINFO));
			//si.cb = sizeof(STARTUPINFO);
			//si.lpDesktop = NULL;

			AllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_LOW_RID, 0, 0, 0, 0, 0, 0, 0, &pIntegritySid);

			tml.Label.Attributes = SE_GROUP_INTEGRITY;
			tml.Label.Sid = pIntegritySid;
			

			SetTokenInformation(hNewToken, TokenIntegrityLevel, &tml, (sizeof(tml) + GetLengthSid(pIntegritySid)));
			// Spin up the new process
			PHANDLE AlternativeHandle = NULL;
			
			PSID RestrictedSids;
			AllocateAndInitializeSid(&MLAuthority, 1, SECURITY_MANDATORY_UNTRUSTED_RID, 0, 0, 0, 0, 0, 0, 0, &RestrictedSids);

			CreateRestrictedToken(hNewToken, NULL, 1, (PSID_AND_ATTRIBUTES)pIntegritySid, 0, 0, 1, NULL, AlternativeHandle);
			
			
			
			//PROCESS_INFORMATION pi;
			if (CreateProcessAsUser(
				hNewToken,
				wszPath, NULL,
				NULL, NULL,
				FALSE, CREATE_SUSPENDED,
				NULL, NULL,
				&si, &pi)) {

				// Place the process in the job.
				// Note: if this process spawns any children, the children are
				//        automatically associated with the same job
				AssignProcessToJobObject(hjob, pi.hProcess);

				// Now, we can allow the child process's thread to execute code.
				ResumeThread(pi.hThread);
				CloseHandle(pi.hThread);

				// Wait for the process to terminate or for all the job's allotted CPU time
				// to be used
				HANDLE h[3];
				h[0] = pi.hProcess;
				h[1] = hjob;
				h[2] = hMapFile;
				DWORD dw = WaitForMultipleObjects(2, h, FALSE, INFINITE);
				DWORD dwExitCode;
				switch (dw - WAIT_OBJECT_0) {
				case 0:
					// The process has terminated…
					break;
				case 1:
					// All of the job's allotted CPU time was used…
					break;
				}
				//The Child Process terminated; Get its Exit Code
				GetExitCodeProcess(pi.hProcess, &dwExitCode);

				//If program Exits Succesffuly then it is a OK :)
				printf("Program Executed with %ld\n", dwExitCode);
				if (dwExitCode != 0)
				{
					//BAD PROGRAM
				}
				else {
					//Hopefully Good Program :)
				}
				//Closes The process as soon as it is no longer Nedded
				CloseHandle(pi.hProcess);
				CloseHandle(hMapFile); //Mapping File Handle
				CloseHandle(hjob);
				CloseHandle(pi.hThread);
				


			}
			else {
				fStatus = GetLastError();
				fwprintf(stderr, L"CreateProcessAsUser failed (%lu)\n", fStatus);
			}
		}
		else {

		fStatus = GetLastError();
			
		}

		SaferCloseLevel(hAuthzLevel);

	}
	else {
		fStatus = GetLastError();
	}

	return fStatus;
}