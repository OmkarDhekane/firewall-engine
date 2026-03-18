#include <iostream>
#include <WS2tcpip.h> //windosock header
#include <thread>
#include <mutex>
#include "../include/parser/packet_parser.h" // to test and parse packet
#include "../firewall/firewall_engine.h"

#pragma comment (lib, "ws2_32.lib")
std::mutex coutMutex;

using namespace std;

string trim(const string& s) {
	size_t start = 0;
	while (start < s.size() && isspace(static_cast<unsigned char>(s[start]))) {
		start++;
	}

	size_t end = s.size();
	while (end > start && isspace(static_cast<unsigned char>(s[end - 1]))) {
		end--;
	}

	return s.substr(start, end - start);
}

void handleClientMulti(SOCKET clientSocket) {

	// handle the client sent data...
	//while loop: accept and echo message back to clietn
	char buf[4096];

	while (true) {
		ZeroMemory(buf, 4096);

		// wait for client to send data
		int bytesReceived = recv(clientSocket, buf, 4096, 0);
		if (bytesReceived == SOCKET_ERROR) {
			cerr << "Error in recv(). Quitting" << endl;
			break;
		}
		if (bytesReceived == 0) {
			cout << "Client Disconnected " << endl;
			break;
		}

		cout << "[Thread " << this_thread::get_id() << "] Received: " << string(buf, bytesReceived) << endl;

		// send the info back
		int bytesSent = send(clientSocket, buf, bytesReceived, 0);
		if (bytesSent == SOCKET_ERROR) {
			cerr << "Error in send(). Quitting" << endl;
			break;
		}

	}

	// close the socket
	closesocket(clientSocket);
}


void testParser(SOCKET clientSocket) {

	//print the thread info
	{
		lock_guard<mutex> lock(coutMutex);
		cout << "[Thread " << this_thread::get_id() << "] Parser test started" << endl;
	}

	// keep on reading the stream from client and buffer it
	char buff[4096];
	while (true) {

		ZeroMemory(buff, 4096);
		
		int bytesReceived = recv(clientSocket, buff, 4096, 0);
		
		if (bytesReceived == SOCKET_ERROR) {
			lock_guard<mutex> lock(coutMutex);
			cerr << "[Thread " << this_thread::get_id() << "] Error in recv(). Closing client connection" << endl;
			break;
		}
		if (bytesReceived == 0) {
			lock_guard<mutex> lock(coutMutex); // the lock is released automatically when it scope ends
			cout << "[Thread " << this_thread::get_id() << "] Client disconnected" << endl;
			break;
		}

		string request(buff, bytesReceived);
		request = trim(request);
		if (request.empty()) {
			continue;
		}
		{
			lock_guard<mutex> lock(coutMutex);
			cout << "[Thread " << std::this_thread::get_id() << "] raw request received" << request << endl;
		}

		PacketMetadata packet;
		bool parseOk = false;

		try {
			parseOk = parsePacket(request, packet);
		}
		catch (const exception& e) {
			string errorMsg = string("error: parse exception: ") + e.what() + "\n";
			send(clientSocket, errorMsg.c_str(), static_cast<int>(errorMsg.size()), 0);
			{
				lock_guard<mutex> lock(coutMutex);
				cerr << "[Thread " << this_thread::get_id() << "] Parser Exception: " <<e.what() << endl;
			}
			continue;
		}

		if (!parseOk) {
			std::string errorMsg = "ERROR: malformed packet\n";
			int bytesSent = send(clientSocket, errorMsg.c_str(), static_cast<int>(errorMsg.size()), 0);
			if (bytesSent == SOCKET_ERROR) {
				lock_guard<mutex> lock(coutMutex);
				cerr << "[Thread " << this_thread::get_id() << "] Error sending malformed packet response" << endl;
				break;
			}
			{
				lock_guard<mutex> lock(coutMutex);
				cerr << "[Thread " << this_thread::get_id() << "] Packet parse failed" << endl;
			}
			continue;
		}


		// parsing success and is correct
		/*{
			lock_guard<mutex> lock(coutMutex);
			cout << "[Thread " << this_thread::get_id() << "] Parsed Packet: " << endl;
			cout << "  SRC_IP: " << packet.SRC_IP << "\t" << "SRC_PORT: " << packet.SRC_PORT << endl;
			cout << "  DST_IP: " << packet.DST_IP << "\t" << "DST_PORT: " << packet.DST_PORT << endl;
			cout << "  PROTOCOL: " << packet.PROTOCOL << endl;
		}*/
		RuleEngine engine;
		RuleDecision decision = engine.evaluate(packet);

		{
			lock_guard<mutex> lock(coutMutex);
			cout << "[Thread " <<this_thread::get_id() << "] Parsed Packet:" << endl;
			cout << "  SRC_IP: " << packet.SRC_IP << "\tSRC_PORT: " << packet.SRC_PORT << endl;
			cout << "  DST_IP: " << packet.DST_IP << "\tDST_PORT: " << packet.DST_PORT << endl;
			cout << "  PROTOCOL: " << packet.PROTOCOL << endl;
			cout << "  Decision: " << decision.action << " (rule_id=" << decision.matchingRuleId << ")" << endl;
		}


		// notify client that packet is parsed successfully

		string response = "Packet parsed successfully.\t";
		response +=  decision.action + " rule_id=" + to_string(decision.matchingRuleId) + "\n";
		int bytesSent = send(clientSocket, response.c_str(), static_cast<int>(response.size()), 0);
		if (bytesSent == SOCKET_ERROR) {
			lock_guard<mutex> lock(coutMutex);
			cerr << "[Thread " << this_thread::get_id() << "] Error in send(). Closing the client Connection" << endl;
			break;
		}

	}
	
	closesocket(clientSocket);
}




int run_multi_threaded_server() {

	// init winsock
	WSADATA wsData;
	WORD ver = MAKEWORD(2, 2);

	// windows needs explicit init of winsock to use winsock functions
	int wsok = WSAStartup(ver, &wsData);
	if (wsok != 0) {
		cout << "Can't initialize winsock! Quitting" << endl;
		return 1;
	}

	// create a socket
	SOCKET listening = socket(
		AF_INET, //address family ipv4
		SOCK_STREAM, // open a 'tcp' socket
		0 // flag;
	);

	if (listening == INVALID_SOCKET) {
		cerr << "Can't create a socket! Quitting" << endl;
		WSACleanup();
		return 1;
	}

	// bind the socket to an IP+PORT
	sockaddr_in hint;
	hint.sin_family = AF_INET;
	hint.sin_port = htons(54000); //htons -> host to network short (little -> big endian)
	hint.sin_addr.S_un.S_addr = INADDR_ANY; // stores 0.0.0.0

	int statusB = bind(listening, (sockaddr*)&hint, sizeof(hint));
	if (statusB == SOCKET_ERROR) {
		cerr << "Error binding. Quitting" << endl;
		closesocket(listening);
		WSACleanup();
		return 1;
	}


	// tell winsock that the socket is for 'listening'
	int statusL = listen(listening, SOMAXCONN); //listen() marks the socket as passive; accept() actually accepts connections.
	if (statusL == SOCKET_ERROR) {
		cerr << "Listening Failed. Quitting" << endl;
		closesocket(listening);
		WSACleanup();
		return 1;
	}

	while (true) {
		sockaddr_in client; 				// wait for a connection
		int clientSize = sizeof(client);	// get size of client

		// wait the client, if present, accept client and create a new socket for that client. 
		// Fill client's info into a struct and return a new socket so we can communicate with it
		SOCKET clientSocket = accept(listening, (sockaddr*)&client, &clientSize);
		if (clientSocket == INVALID_SOCKET) {
			cerr << "Accept failed. Waiting for next client..." << endl;
			continue;
		}

		char host[NI_MAXHOST]; // client's remote name
		char service[NI_MAXSERV]; // service (i.e. port) the client is connec on


		// ####### START This code block exists just to print client's basic info  ####### 
		ZeroMemory(host, NI_MAXHOST); // fill-in with zero
		ZeroMemory(service, NI_MAXSERV);

		if (getnameinfo((sockaddr*)&client, clientSize, host, NI_MAXHOST, service, NI_MAXSERV, 0) == 0) {
			cout << host << " connected on port " << service << endl;
		}
		else {
			inet_ntop(AF_INET, &client.sin_addr, host, NI_MAXHOST);
			cout << host << " connected on port " << ntohs(client.sin_port) << endl;
		}
		// ####### END This code block exists just to print client's basic info  ####### 

		// single threaded
		//handleClientMulti(clientSocket);
		
		// multi-threaded
		// thread t(handleClientMulti, clientSocket);
		// t.detach();

		thread t(testParser, clientSocket);
		t.detach();
	}

	//close listening socket
	closesocket(listening); // ideally, we don't close it so other clients can connect to it

	// cleanup winsock
	WSACleanup();

	return 0;
}