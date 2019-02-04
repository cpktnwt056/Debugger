#include<iostream>
#include<windows.h>
#include<Tlhelp32.h>
#include<iomanip>  
#include<fstream>
#include<map>
#include<vector>
using namespace std;
//Usage:
//Attach => bp_set(address,pHandlerFunc handler=NULL) => run
//
//typedef DWORD (*pHandlerFunc)(_arg); 
//
//Dr7 stuff:
#define HW_EXECUTE 0
#define HW_ACCESS 3 
#define HW_WRITE 1
//Thread

//#ifndef DECLSPEC_GUARDNOCF
#ifdef _WIN64
#define WIDTH 16 
#define FullIP(context) (context.Rip)
#define FullAX(context) (context.Rax)
#define FullBX(context) (context.Rbx)
#define FullCX(context) (context.Rcx)
#define FullDX(context) (context.Rdx)
#define FullSP(context) (context.Rsp)
#define FullBP(context) (context.Rbp)
#define FullSI(context) (context.Rsi)
#define FullDI(context) (context.Rdi)
#else
#define WIDTH 8
#define FullIP(context) (context.Eip)
#define FullAX(context) (context.Eax)
#define FullBX(context) (context.Ebx)
#define FullCX(context) (context.Ecx)
#define FullDX(context) (context.Edx)
#define FullSP(context) (context.Esp)
#define FullBP(context) (context.Ebp)
#define FullSI(context) (context.Esi)
#define FullDI(context) (context.Edi)
#endif 
struct module_t{
	HANDLE hModule;
	BYTE* dwBase;
	DWORD dwSize;
};
struct _hw_bp{
	ULONG_PTR address;
	int		length;
	DWORD 	condition;
};
//#define RVA2VA(type,base,rva) type(ULONG_PTR(base) + rva)
#define RVA2VA(type,base,rva) (type)((ULONG_PTR)base + rva)
//template<class AT>//AT == DWORD // DWORD64
class _Debugger{
public:
	
	struct _arg{
		_Debugger *pDbg;
		DEBUG_EVENT event;
		CONTEXT 	context;
	};
	struct _bp{
		BYTE	byte;//origin BYTE
		bool 	hasHandler;
		//ULONG_PTR	HandlerAddress;
		//pHandlerFunc handler;
		DWORD (* handler)(_arg);
	};
	typedef DWORD (*pHandlerFunc)(_arg);
	
	map<ULONG_PTR,_bp>	Addr2_bp;//address => originbyte
private:
	//DWORD 	excpetion_code;
	PVOID 	exception_address;
	
	map<int,_hw_bp>		hw_bp;
	vector<DWORD>		threads;//obtain by calling enumThread

	bool	enumThread();
	CONTEXT get_thread_context(DWORD Tid);
	void getDebugEvent();
	DWORD exception_handler_breakpoint();
	DWORD exception_handler_single_step(CONTEXT context);
	//bool SetHandler(ULONG_PTR address,func);
	template<typename T>
	static void printModule64(MODULEENTRY32 pe32,T &stream);
public:
	HANDLE	hProcess;
	DWORD	dwPid;
	bool 	debugger_active;//control run() 
	
	_Debugger(){
		debugger_active = false;
	}
	module_t GetModule(string);
	//ULONG_PTR GetFuncAddress(string dll,string func);
	PVOID GetFuncAddress(string dll,string func);
	bool attach(string);//dwPid / hProcess
	bool attach(DWORD);//dwPid / hProcess
	bool detach();
	bool bp_set(ULONG_PTR Address,pHandlerFunc func=NULL);
	bool bp_set_hw(ULONG_PTR Address,int length,DWORD condition);
	bool bp_del_hw(int slot);
	void run();
	
	//SnapShotProcess
	//void error(char*);
	void* FunctionResolve(char* dllName,char* funcName);
	bool SuspendAllThreads();
	bool ReadMemory64(ULONG_PTR Address,BYTE* buf,SIZE_T length);
	SIZE_T WriteMemory64(ULONG_PTR Address,BYTE* buf,SIZE_T length);
	static SIZE_T writeProcessMemory(DWORD PID,LPVOID Address,BYTE* buf,SIZE_T length);
	static bool readProcessMemory(DWORD PID,LPVOID Address,BYTE* buf,SIZE_T length);
	//--------------------------
	//static bool functionResolve(string dllName,string funcName);
	static DWORD GetPid(string);
	static void* GetModuleBaseAddress(DWORD PID,char* ModuleName);
	static void error(char*);
	static bool InjectDLLA(string dllName, string processName);
	template<typename T>
	static bool printThread64(DWORD Tid,T& stream);
	template<typename T>
	static void listThread(DWORD PID,T &stream);
	template<typename T>
	static void listModule(DWORD PID,T &stream);
};
void _Debugger::error(char* message){
	printf("%s (%d)\n",message,GetLastError());
}
bool _Debugger::attach(string processName){
	PROCESSENTRY32 pe32 = {sizeof(PROCESSENTRY32)};
	this->dwPid = GetPid(processName);
	if(dwPid){
		this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,dwPid);
		if(this->hProcess){
			if(DebugActiveProcess(dwPid)){
				//debugger_active = true;
				//run();
			}else{
				cout << "DebugActiveProcess fail! (error code: " <<  GetLastError() << ")" << endl;//50:ERROR_NOT_SUPPORTED 
				return false;	
			}
		}else{
			cout << "OpenProcess fail!" << endl;
			return false;
		}
	}else{
		cout << "attach GetPid fail" << endl;
		return false;
	}
	return true;//0 For system idle process
}
bool _Debugger::attach(DWORD PID){
	this->dwPid = PID;
	if(dwPid){
		this->hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE,dwPid);
		if(this->hProcess){
			if(DebugActiveProcess(dwPid)){
				return true;
			}else	cout << "DebugActiveProcess fail! (error code: " <<  GetLastError() << ")" << endl;//50:ERROR_NOT_SUPPORTED 
		}else	cout << "OpenProcess fail!" << endl;
	}else	cout << "attach GetPid fail" << endl;
	return false;//0 For system idle process
}

bool _Debugger::detach(){
	if(DebugActiveProcessStop(dwPid)){
		cout << "detach OK!" << endl;
		return true;
	}else{
		cout << "detach error! (error code: " <<  GetLastError() << ")" << endl; //access denied
		return false;
	}
}


//template<typename T>//DWORD / ULONG_PTR
bool _Debugger::bp_set(ULONG_PTR Address,pHandlerFunc func){
	BYTE originByte;
	//if(ReadMemory64(Address,&originByte,1)){
	printf("Reading %p\n",Address);
	if(ReadProcessMemory(this->hProcess,(PVOID)Address,&originByte,1,NULL)){
		if(WriteProcessMemory(this->hProcess,(LPVOID)Address,"\xCC",1,NULL)){
			_bp temp;
			temp.byte = originByte;
			//cout << "func address " << func << endl;
			if(func){
				temp.handler = func;
				temp.hasHandler = true;
			}else{
				temp.hasHandler = false;
				temp.handler = NULL;
			}
			Addr2_bp[Address] = temp;
			return true;	
		}else	cout << "Write fail!" << endl;
	}else error("Read fail!");//cout << "Read fail!" << endl;
	return false;
}
bool _Debugger::bp_set_hw(ULONG_PTR Address,int length,DWORD condition){
	if(!(length==1 ||length==2 || length==4))	return false;
	else	length -= 1;
	if(!(condition==HW_EXECUTE || condition==HW_ACCESS || condition==HW_WRITE)) return false;	
	int available;
	if(hw_bp.find(0)==hw_bp.end())
		available = 0;
	else if(hw_bp.find(1)==hw_bp.end())
		available = 1;
	else if(hw_bp.find(2)==hw_bp.end())
		available = 2;
	else if(hw_bp.find(3)==hw_bp.end())
		available = 3;
	else	return false;
	if(enumThread()){
		for(vector<DWORD>::iterator it=threads.begin(); it != threads.end(); it++){
	
			CONTEXT context = get_thread_context(*it);
			context.Dr7 |= 1 << (available * 2);
			switch(available){
				case 0:
					context.Dr0 = Address;
					break;
				case 1:
					context.Dr1 = Address;
					break;
				case 2:
					context.Dr2 = Address;
					break;
				case 3:
					context.Dr3 = Address;
					break;
				//default:
					//return false;
			}
			context.Dr7 |= condition << ((available * 4) + 16);
			context.Dr7 |= length << ((available * 4) + 18);
			
			HANDLE hThread	= OpenThread(THREAD_ALL_ACCESS,FALSE,*it);
			SetThreadContext(hThread,&context);
			_hw_bp t; t.address=Address; t.condition=condition; t.length=length;
			hw_bp[available] = t;
			CloseHandle(hThread);
		}
		return true;
	}else	return false;
}
bool _Debugger::bp_del_hw(int slot){
	if(enumThread()){
		for(vector<DWORD>::iterator it=threads.begin(); it != threads.end(); it++){
			HANDLE hThread	= OpenThread(THREAD_ALL_ACCESS,FALSE,*it);
			CONTEXT context;
			GetThreadContext(hThread,&context);
			context.Dr7 &= ~(1 << (slot * 2));	
			switch(slot){
				case 0:
					context.Dr0 = 0;
					break;
				case 1:
					context.Dr1 = 0;
					break;
				case 2:
					context.Dr2 = 0;
					break;
				case 3:
					context.Dr3 = 0;
					break;
				//default:
					//return false;
			}
			context.Dr7 &= ~(3 << ((slot * 4) + 16));//condition
			context.Dr7 &= ~(3 << ((slot * 4) + 18));//length	
			SetThreadContext(hThread,&context);
			threads.erase(it);
		}
		return true;
	}else	return false;
}
void* _Debugger::FunctionResolve(char* dllName,char* funcName){
	PVOID pBase = GetModuleBaseAddress(this->dwPid,dllName);
	if(pBase){
		IMAGE_DOS_HEADER dos;// = PIMAGE_DOS_HEADER(pBase);
		IMAGE_NT_HEADERS nt;// RVA2VA(PIMAGE_NT_HEADERS,pBase,dos->e_lfanew);
		if(ReadProcessMemory(this->hProcess,pBase,&dos,sizeof(dos),NULL)){
			if(ReadProcessMemory(this->hProcess,RVA2VA(PVOID,pBase,dos.e_lfanew),&nt,sizeof(nt),NULL)){
				//nt.OptionalHeader.AddressOfEntryPoint
				if(nt.Signature == IMAGE_NT_SIGNATURE){
					IMAGE_EXPORT_DIRECTORY exp;// = RVA2VA(PIMAGE_EXPORT_DIRECTORY,pBase,nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
					//char* dllName = RVA2VA(PCHAR,pBase,exp->Name);
					if(!ReadProcessMemory(this->hProcess,RVA2VA(PVOID,pBase,nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress),&exp,sizeof(exp),NULL))	return 0;
					DWORD cnt = exp.NumberOfNames;
					char buf[50];
					
					
					DWORD adr[cnt];// = RVA2VA(PDWORD,pBase,exp.AddressOfFunctions);//addressTable
					DWORD sym[cnt];// = RVA2VA(PDWORD,pBase,exp.AddressOfNames);//nameTable
					WORD  ord[cnt];//= RVA2VA(PWORD, pBase, exp.AddressOfNameOrdinals);
					if(!ReadProcessMemory(this->hProcess,RVA2VA(PVOID,pBase,exp.AddressOfFunctions),adr,sizeof(adr),NULL))	return 0;//AddressOfFunctions
					if(!ReadProcessMemory(this->hProcess,RVA2VA(PVOID,pBase,exp.AddressOfNames),sym,sizeof(sym),NULL))	return 0;//
					if(!ReadProcessMemory(this->hProcess,RVA2VA(PVOID,pBase,exp.AddressOfNameOrdinals),ord,sizeof(ord),NULL))	return 0;
					char  api[50];
					PVOID api_adr;
					for(int i=0; i<cnt;i++){
						if(!ReadProcessMemory(this->hProcess,RVA2VA(PVOID,pBase,sym[i]),&api,sizeof(api),NULL))	return 0;
						api_adr = RVA2VA(LPVOID, pBase, adr[ord[i]]);
						if(!strcmp(funcName,api))
							return api_adr;
							//api_adr = RVA2VA(LPVOID, pBase, adr[ord[i]]);
							//if(!ReadProcessMemory(this->hProcess,RVA2VA(PVOID,pBase,adr[ord[i]]),&api_adr,sizeof(api_adr),NULL))	return 0;
						printf("scan function : %-30s at %p\n",api,api_adr);
					}
				}
			}
		}
	}
	return 0;
}

bool _Debugger::SuspendAllThreads(){
	if(enumThread()){
		for(int i=0; i<threads.size(); i++){
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,threads[i]);
			cout << "Suspend thread id : " << threads[i] << endl;
			SuspendThread(hThread);
			CloseHandle(hThread);
		}
		//HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,)
		return true;
	}
	return false;
}
//------------------Wrapper----------------------------
module_t _Debugger::GetModule(string szModule){
	MODULEENTRY32 pe32 = {sizeof(MODULEENTRY32)};
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, NULL);
	if( Module32First(hSnapShot, &pe32) ){
		if( !strcmp(szModule.c_str(),pe32.szModule)){
			//dwPid = pe32.th32ProcessID;
			//hProcess = OpenProcess(PROCESS_ALL_ACCESS, dwPid);
			CloseHandle(hSnapShot);
			return {pe32.hModule,pe32.modBaseAddr,pe32.modBaseSize};
		}
		while( Module32Next(hSnapShot, &pe32)){
			//cout << "scanning:(" << pe32.szExePath << "):" <<pe32.szModule << endl;
			if( !strcmp(szModule.c_str(),pe32.szModule)){
				CloseHandle(hSnapShot);
				return {pe32.hModule,pe32.modBaseAddr,pe32.modBaseSize};	
			}
		}
	}
	CloseHandle(hSnapShot);
	return module_t();//0 For system idle process
} 

DWORD _Debugger::GetPid(string processName){
	PROCESSENTRY32 pe32 = {sizeof(PROCESSENTRY32)};
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if( Process32First(hSnapShot, &pe32) ){
		if( !strcmp(processName.c_str(),pe32.szExeFile)){
		
			CloseHandle(hSnapShot);
			return pe32.th32ProcessID;
		}
		while( Process32Next(hSnapShot, &pe32)){
			//cout << "scanning:" << pe32.szExeFile << endl;
			if(!strcmp(processName.c_str(),pe32.szExeFile)){
				CloseHandle(hSnapShot);
				return pe32.th32ProcessID;
			}
		}
	}
	CloseHandle(hSnapShot);
	return 0;//0 For system idle process
}

PVOID _Debugger::GetFuncAddress(string dll,string func){
	HMODULE hModule = GetModuleHandleA(dll.c_str());
	if(hModule){
		PVOID Address = (PVOID)GetProcAddress(hModule,func.c_str());	
		CloseHandle(hModule);
		return Address;
	}
	CloseHandle(hModule);
	return 0;
}
void* _Debugger::GetModuleBaseAddress(DWORD PID,char* ModuleName){
	MODULEENTRY32 pe32 = {sizeof(MODULEENTRY32)};
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	if( Module32First(hSnapShot, &pe32) ){
		if(!strcmp(pe32.szModule,ModuleName))
			return pe32.modBaseAddr;
		while( Module32Next(hSnapShot, &pe32)){
			if(!strcmp(pe32.szModule,ModuleName))	return pe32.modBaseAddr;
		}
	}else	cout << "fail! error CODE:" << GetLastError() << endl;
	CloseHandle(hSnapShot);
	return 0;
}
CONTEXT _Debugger::get_thread_context(DWORD Tid){
	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	HANDLE hThread  = OpenThread(THREAD_ALL_ACCESS,FALSE,Tid);
	if(hThread){
		GetThreadContext(hThread,&context);
		CloseHandle(hThread);
		return context;
	}
	return context;
}
bool _Debugger::ReadMemory64(ULONG_PTR Address,BYTE* buf,SIZE_T length){
	if(ReadProcessMemory(this->hProcess,(LPVOID)Address,buf,length,0))	return true;
	return false;
}
SIZE_T _Debugger::WriteMemory64(ULONG_PTR Address,BYTE* buf,SIZE_T length){
	SIZE_T written=0;
	WriteProcessMemory(this->hProcess,(LPVOID)Address,buf,length,&written);
	return written;
}
SIZE_T _Debugger::writeProcessMemory(DWORD PID,LPVOID Address,BYTE* buf,SIZE_T length){
	HANDLE _hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,PID);
	if(_hProcess){
		SIZE_T writen;
		if(WriteProcessMemory(_hProcess,Address,buf,length,&writen)){
			CloseHandle(_hProcess);
			return writen;
		}else cout << "WriteProcessMemory fail! (error code : " << GetLastError() << ")" << endl;
	}//else cout << "OpenProcess fail!" << endl;
	CloseHandle(_hProcess);
	return 0;
}
bool _Debugger::readProcessMemory(DWORD PID,LPVOID Address,BYTE* buf,SIZE_T length){
	HANDLE _hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,PID);
	if(_hProcess){
		if(ReadProcessMemory(_hProcess,Address,buf,length,NULL)){
			CloseHandle(_hProcess);
			return false;
		}else cout << "ReadProcessMemory fail! (error code : " << GetLastError() << ")" << endl;
	}//else cout << "OpenProcess fail!" << endl;
	CloseHandle(_hProcess);
	return 0;
}
template<typename T>
void _Debugger::printModule64(MODULEENTRY32 pe32,T &stream){
	ios state(NULL);  
	stream << "path:" << pe32.szExePath << endl;
	stream << "name:" << pe32.szModule << endl;
	state.copyfmt(cout); // save current formatting  
	stream << "address:0x"<< hex << setw(8) << setfill('0') << (ULONG_PTR)pe32.modBaseAddr << endl;
	//stream << "address:0x"<< hex << setw(8) << setfill('0') << (ULONG_PTR)pe32.modBaseAddr << endl;
	stream.copyfmt(state); // restore previous formatting  
	stream << "size:" << pe32.modBaseSize << endl;
	stream << "handle:" << pe32.hModule << endl;
	//stream << "ProccntUsage:" << pe32.ProccntUsage << endl;
	//stream << "GlblcntUsage:" << pe32.GlblcntUsage << endl;
	stream << "ModuleID:" << pe32.th32ModuleID << endl;
	//stream << "ProcessID :" << pe32.th32ProcessID << endl;
	stream << "----------------" << endl;
}
template<typename T>
void _Debugger::listModule(DWORD PID,T &stream){
	stream << "ProcessID :" << PID << endl;
	MODULEENTRY32 pe32 = {sizeof(MODULEENTRY32)};
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, PID);
	cout << hSnapShot<< endl;
	if( Module32First(hSnapShot, &pe32) ){
		printModule64(pe32,stream);
		while( Module32Next(hSnapShot, &pe32)){
			//cout << "scanning:(" << pe32.szExePath << "):" <<pe32.szModule << endl;
			printModule64(pe32,stream);
		}
	}else
		cout << "fail! error CODE:" << GetLastError() << endl;
	CloseHandle(hSnapShot);
}
template<typename T>
bool _Debugger::printThread64(DWORD Tid,T& stream){
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,Tid);
	if(hThread==NULL)	return false;
	CONTEXT thread_context;
	if(!GetThreadContext(hThread,&thread_context))	return false;
	ios state(NULL);  
	state.copyfmt(cout); // save current formatting  
	//printf("[*] Dumping registers for thread ID: 0x%08x",thread);
	stream << "[*] Dumping registers for thread ID: 0x" << hex << setw(WIDTH) << setfill('0') << Tid << endl;
	stream << "[**] IP: 0x" << hex << setw(WIDTH) << setfill('0') << FullIP(thread_context) << endl;
	stream << "[**] SP: 0x" << hex << setw(WIDTH) << setfill('0') << FullSP(thread_context) << endl;
	stream << "[**] BP: 0x" << hex << setw(WIDTH) << setfill('0') << FullBP(thread_context) << endl;
	stream << "[**] SI: 0x" << hex << setw(WIDTH) << setfill('0') << FullSI(thread_context) << endl;
	stream << "[**] DI: 0x" << hex << setw(WIDTH) << setfill('0') << FullDI(thread_context) << endl;
	stream << "[**] AX: 0x" << hex << setw(WIDTH) << setfill('0') << FullAX(thread_context) << endl;
	stream << "[**] BX: 0x" << hex << setw(WIDTH) << setfill('0') << FullBX(thread_context) << endl;
	stream << "[**] CX: 0x" << hex << setw(WIDTH) << setfill('0') << FullCX(thread_context) << endl;
	stream << "[**] DX: 0x" << hex << setw(WIDTH) << setfill('0') << FullDX(thread_context) << endl;
	stream.copyfmt(state); //restore
	CloseHandle(hThread);
	return true;
}
bool _Debugger::InjectDLLA(string dllName, string processName){
	bool bOK=false;
	DWORD PId = _Debugger::GetPid(processName);
	if(PId!=0){
		cout << processName << "   PId = " << PId << endl;
		//HANDLE hProcess = GetProcessHandle(PId);
		HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE, FALSE, PId);
		if(hProcess!=0){
			//cout << "hProcess = " << hProcess << endl;
			HANDLE hThread;
			LPTHREAD_START_ROUTINE lpStartAddress = (LPTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandleA("kernel32.dll"),"LoadLibraryA");
			printf("LoadLibraryA @ %p\n",lpStartAddress);//OK
			if(lpStartAddress==0)	return false;
			LPVOID dllRemoteName = VirtualAllocEx(hProcess, NULL, dllName.length()+1, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
			SIZE_T length = dllName.length()+1;
			char DllName[length] = {0};
			strcpy(DllName,dllName.c_str());
			//if( WriteProcessMemory(hProcess, dllRemoteName, (PVOID)dllName.c_str(), length, NULL)){//WCHAR to PVOID !? string to PVOID !?
			if( WriteProcessMemory(hProcess, dllRemoteName, DllName, length, NULL)){//WCHAR to PVOID !? string to PVOID !?
				printf("Wirte in path at %p\n",dllRemoteName);
				hThread = CreateRemoteThread(hProcess, NULL, 0, lpStartAddress, dllRemoteName, 0, NULL);
				WaitForSingleObject(hThread, 3000);//!
				bOK = true;
			}
			//clean
			//if(dllRemoteName != NULL)
				//VirtualFreeEx(hProcess, dllRemoteName, 0, MEM_RELEASE);
			if(hThread!=NULL)
				CloseHandle(hThread);
			if(hProcess!=NULL)
				CloseHandle(hProcess);
		}else 
			cout << "GetProcessHandle(" << PId << ")  failed !" << endl;
	}
	return bOK;
} 

/*template<typename T>
void _Debugger::printThread32(DWORD Tid,T& stream){
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,Tid);
	if(hThread==NULL)	return;
	CONTEXT thread_context;
	GetThreadContext(hThread,&thread_context);
	ios state(NULL);  
	state.copyfmt(cout); // save current formatting  
	//printf("[*] Dumping registers for thread ID: 0x%08x",thread);
	stream << "[*] Dumping registers for thread ID: 0x" << hex << setw(16) << setfill('0') << Tid << endl;
	stream << "[**] EIP: 0x" << hex << setw(8) << setfill('0') << thread_context.Eip << endl;
	stream << "[**] ESP: 0x" << hex << setw(8) << setfill('0') << thread_context.Esp << endl;
	stream << "[**] EBP: 0x" << hex << setw(8) << setfill('0') << thread_context.Ebp << endl;
	stream << "[**] EAX: 0x" << hex << setw(8) << setfill('0') << thread_context.Eax << endl;
	stream << "[**] EBX: 0x" << hex << setw(8) << setfill('0') << thread_context.Ebx << endl;
	stream << "[**] ECX: 0x" << hex << setw(8) << setfill('0') << thread_context.Ecx << endl;
	stream << "[**] EDX: 0x" << hex << setw(8) << setfill('0') << thread_context.Edx << endl;
	stream.copyfmt(state); //restore
	CloseHandle(hThread);
}*/
template<typename T>
void _Debugger::listThread(DWORD PID,T &stream){
	
	THREADENTRY32 te32 = {sizeof(THREADENTRY32)};
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,PID);
	if( Thread32First(hSnapShot, &te32) ){
		if(te32.th32OwnerProcessID==PID)
			printThread64(te32.th32ThreadID,stream);
		while( Thread32Next(hSnapShot, &te32)){
			//cout << "scanning:(" << pe32.szExePath << "):" <<pe32.szModule << endl;
			if(te32.th32OwnerProcessID==PID)
				printThread64(te32.th32ThreadID,stream);
		}
	}else
		cout << "fail! error CODE:" << GetLastError() << endl;
	CloseHandle(hSnapShot);
}


//----------------------------------------------
void _Debugger::run(){
	debugger_active = true;
	while(debugger_active){
		getDebugEvent();
	}
}
//RETURN : DBG_EXCEPTION_NOT_HANDLED / DBG_CONTINUE
void _Debugger::getDebugEvent(){
	DEBUG_EVENT debug_event;
	DWORD continue_status = DBG_CONTINUE;
	//ios state(NULL);
	//state.copyfmt(cout);
	if(WaitForDebugEvent(&debug_event,INFINITE)){
		//system("pause");
		CONTEXT thread_context = get_thread_context(debug_event.dwThreadId);
		//printf("Event Code: %d,Thread ID:%d,Address :%016x\n",debug_event.dwDebugEventCode, debug_event.dwThreadId ,thread_context.Rip);
		//cout << "Event Code: " << debug_event.dwDebugEventCode << ",Thread ID: " << debug_event.dwThreadId << ",Address : " << hex << thread_context.Rip << endl;
		map<ULONG_PTR,_bp>::iterator it = Addr2_bp.find(FullIP(thread_context)-1);  //! notice 
		if(it != Addr2_bp.end()){//bp_SET
			if(it->second.hasHandler){//eip is has regist
				if(WriteProcessMemory(this->hProcess,(PVOID)FullIP(thread_context)-1,&it->second.byte,1,NULL)){//WRITE origin
					
				}else	cout << "Write origin false";
				_arg arg;
				arg.context = thread_context;
				arg.event	= debug_event;
				arg.pDbg = this;
				continue_status = it->second.handler(arg);//Addr2_bp[FullIP(thread_context)].
				WriteProcessMemory(this->hProcess,(PVOID)FullIP(thread_context)-1,"\xCC",1,NULL);//WRITE BACK
				ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId,continue_status);
				return;
			}
		}//else	cout << "not found!" << endl;
		if (debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT){
			DWORD exception = debug_event.u.Exception.ExceptionRecord.ExceptionCode;
			exception_address = debug_event.u.Exception.ExceptionRecord.ExceptionAddress;
			switch(exception){
				case EXCEPTION_ACCESS_VIOLATION:
					printf("Access Violation Detected.\n");
					break;
				case EXCEPTION_BREAKPOINT:
					continue_status = exception_handler_breakpoint();
					break;
				case EXCEPTION_GUARD_PAGE:
					printf("Guard Page Access Detected.\n");
					break;
				case EXCEPTION_SINGLE_STEP://hw_bp
					printf("Single Stepping.\n");
					continue_status = exception_handler_single_step(thread_context);
					break;
			}
		}else	printf("Other EventCode\n");
		//debugger_active = false;
		ContinueDebugEvent(debug_event.dwProcessId,debug_event.dwThreadId,continue_status);
	}
}
DWORD _Debugger::exception_handler_breakpoint(){
	printf("exception address : %p\n",exception_address);
	return DBG_CONTINUE;
}

DWORD _Debugger::exception_handler_single_step(CONTEXT context){
	DWORD continue_status;
	int slot=-1;
	if(context.Dr6 & 0x1 && (hw_bp.find(0) != hw_bp.end())){
		slot = 0;
	}else if(context.Dr6 & 0x2 && (hw_bp.find(1) != hw_bp.end())){
		slot = 1;
	}else if(context.Dr6 & 0x4 && (hw_bp.find(2) != hw_bp.end())){
		slot = 2;
	}else if(context.Dr6 & 0x8 && (hw_bp.find(3) != hw_bp.end())){
		slot = 3;
	}else{
		cout << "not slot!" << endl;
		continue_status = DBG_EXCEPTION_NOT_HANDLED;
	}
	continue_status = DBG_CONTINUE;
	/*if(slot>-1){
		if(bp_del_hw(slot))
			printf("[*] Hardware breakpoint removed.\n");	
		else
			printf("[*] Hardware breakpoint removed fail!.\n");
	}*/
	printf("ip : %p\n",FullIP(context));
	cout << "slot : " << slot << endl;
	return continue_status;
}
bool _Debugger::enumThread(){
	THREADENTRY32 te32 = {sizeof(THREADENTRY32)};
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,dwPid);
	threads.clear();
	if( Thread32First(hSnapShot, &te32) ){
		if(te32.th32OwnerProcessID==dwPid)
			threads.push_back(te32.th32ThreadID);
		while( Thread32Next(hSnapShot, &te32)){
			//cout << "scanning:(" << pe32.szExePath << "):" <<pe32.szModule << endl;
			if(te32.th32OwnerProcessID==dwPid)
				threads.push_back(te32.th32ThreadID);
		}
	}else{
		cout << "Thread32First fail!" << endl;
		CloseHandle(hSnapShot);
		return false;
	}
	CloseHandle(hSnapShot);
	return true;
}
//-----------------------------------
/*
DebugActiveProcess:
DebugActiveProcess can fail if the target process is created with a security descriptor that grants the debugger anything less than full access. 
If the debugging process has the SE_DEBUG_NAME privilege granted and enabled, it can debug any process.
-------NOTE:-------
if other debugger is debuggin targetProcess raise error code:87 
*/

