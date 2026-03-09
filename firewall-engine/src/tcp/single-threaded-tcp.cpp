#include <iostream>
#include <WS2tcpip.h> //windosock header
#include <thread>

#pragma comment (lib, "ws2_32.lib")


using namespace std;

void handleClient(SOCKET clientSocket) {

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

int run_single_threaded_server() {

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

		handleClient(clientSocket);
	}

	//close listening socket
	closesocket(listening); // ideally, we don't close it so other clients can connect to it

	// cleanup winsock
	WSACleanup();

	return 0;
}