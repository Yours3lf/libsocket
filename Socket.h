#pragma once

#include <string>
#include <iostream>
#include <assert.h>

#ifdef _WIN32
#include <winsock2.h>
#include <WS2tcpip.h>

#pragma comment(lib, "ws2_32")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#endif

class socket
{
private:
	static bool isInited;

#ifdef _WIN32
	typedef uint64_t socketType;
#define SOCKET_VALID(x) (x != INVALID_SOCKET)
	const static socketType is = INVALID_SOCKET;
#else
	typedef int32_t socketType;
#define SOCKET_VALID(x) (x >= 0)
	const static socketType is = -1;
#endif
	socketType s = is;

	void convertAddress(const std::string& address, uint16_t port, int family, struct sockaddr* outAddr)
	{
		assert(outAddr);

		addrinfo* addressInfo = 0;
		std::string portStr = std::to_string(port);
		getaddrinfo(address.c_str(), portStr.c_str(), 0, &addressInfo);

		int i = 0;
		for (addrinfo* ptr = addressInfo; ptr != 0; ptr = ptr->ai_next)
		{
			/**
			std::cout << "Getaddrinfo response " << i++ << std::endl;
			std::cout << "Flags " << ptr->ai_flags << std::endl;
			std::cout << "Family ";
			switch (ptr->ai_family)
			{
			case AF_UNSPEC:
				std::cout << "unspec";
				break;
			case AF_INET:
				std::cout << "ipv4";
				break;
			case AF_INET6:
				std::cout << "ipv6";
				break;
			default:
				std::cout << ptr->ai_family;
				break;
			}

			std::cout << std::endl << "Socket type ";
			switch (ptr->ai_socktype)
			{
			case 0:
				std::cout << "unspecified";
				break;
			case SOCK_STREAM:
				std::cout << "stream";
				break;
			case SOCK_DGRAM:
				std::cout << "dgram";
				break;
			case SOCK_RAW:
				std::cout << "raw";
				break;
			case SOCK_RDM:
				std::cout << "rdm";
				break;
			case SOCK_SEQPACKET:
				std::cout << "seqpacket";
				break;
			default:
				std::cout << ptr->ai_socktype;
				break;
			}

			std::cout << std::endl << "Protocol ";
			switch (ptr->ai_protocol)
			{
			case 0:
				std::cout << "unspecified";
				break;
			case IPPROTO_TCP:
				std::cout << "tcp";
				break;
			case IPPROTO_UDP:
				std::cout << "udp";
				break;
			default:
				std::cout << ptr->ai_protocol;
				break;
			}

			std::cout << std::endl;
			std::cout << "Length " << ptr->ai_addrlen << std::endl;
			if (ptr->ai_canonname)
			{
				std::cout << "Canon name " << ptr->ai_canonname << std::endl;
			}
			std::cout << std::endl;
			/**/

			if (family == ptr->ai_family)
			{
				memcpy(outAddr, ptr->ai_addr, ptr->ai_addrlen);
				break;
			}
		}

		freeaddrinfo(addressInfo);
	}

	static void checkErrorMessage(int code)
	{
		if (!code)
			return;

#ifdef _WIN32
		int error = WSAGetLastError();
		char* message = 0;
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, error,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			(LPSTR)&message, 0, NULL);
		std::cerr << std::string(message) << std::endl;
		LocalFree(message);
#else
		std::cerr << std::string(strerror(errno)) << std::endl;
#endif
	}

	//The socket function creates a socket that is bound 
	//to a specific transport service provider.
	void create()
	{
		if (this->isValid())
			return;

#ifdef _WIN32
		s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

		if (s == INVALID_SOCKET)
		{
			checkErrorMessage(1);
		}
#else
#endif
	}

public:
	static int init()
	{
#ifdef _WIN32
		WSADATA wsaData;
		int res = WSAStartup(MAKEWORD(1, 1), &wsaData);;
		if (!res)
		{
			isInited = true;
		}

		checkErrorMessage(res);

		return res;
#else
		isInited = true;
		return 0;
#endif
	}

	static void shutdown()
	{
#ifdef _WIN32
		if (isInited)
		{
			isInited = false;
			int res = WSACleanup();

			checkErrorMessage(res);
		}
#else
		isInited = false;
#endif
	}

	//The closesocket function closes an existing socket.
	void close()
	{
		if (!this->isValid())
			return;

		int status = 0;
#ifdef _WIN32
		status = ::shutdown(s, SD_BOTH);

		//could fail if socket is not connected
		checkErrorMessage(status);

		//if (status == 0)
		{
			status = closesocket(s);

			checkErrorMessage(status);
		}
#else
		status = ::shutdown(s, SHUT_RDWR);

		checkErrorMessage(status);
		
		//if (status == 0)
		{
			status = ::close(s);

			checkErrorMessage(status);
		}
#endif

		s = is;
	}

	socket(socket&& ss)
	{
		s = ss.s;
		ss.s = is;
	}

	socket& operator=(socket&& ss)
	{
		if (this != &ss)
		{
			s = ss.s;
			ss.s = is;
		}

		return *this;
	}
	
	socket& operator=(const socket&) = delete;
	socket(const socket&) = delete;

	~socket()
	{
		close();
	}

	socket() : s(is)
	{
		assert(isInited);
	}

	socket(socketType ss)
	{
		assert(isInited);
		s = ss;
	}

	bool isValid()
	{
		return SOCKET_VALID(s);
	}

	//The connect function establishes a connection to a specified socket.
	int connect(const std::string& address, uint16_t port)
	{
		create();
		assert(this->isValid());

#ifdef _WIN32
		struct sockaddr sockaddr;
		convertAddress(address, port, AF_INET, &sockaddr);

		int res = ::connect(s, &sockaddr, sizeof(sockaddr));

		checkErrorMessage(res);

		return res;
#else
#endif
	}

	//The bind function associates a local address with a socket.
	int bind(const std::string& address, uint16_t port)
	{
		create();
		assert(this->isValid());

#ifdef _WIN32
		struct sockaddr sockaddr;
		convertAddress(address, port, AF_INET, &sockaddr);

		int res = ::bind(s, &sockaddr, sizeof(sockaddr));

		checkErrorMessage(res);

		return res;
#else
#endif
	}

	//The listen function places a socket in a state 
	//in which it is listening for an incoming connection.
	int listen()
	{
		assert(this->isValid());

#ifdef _WIN32
		int res = ::listen(s, SOMAXCONN);

		checkErrorMessage(res);

		return res;
#else
#endif
	}

	socket accept()
	{
		assert(this->isValid());

#ifdef _WIN32
		socketType ss = ::accept(s, 0, 0);

		if (!SOCKET_VALID(ss))
		{
			checkErrorMessage(1);
		}

		return socket(ss);
#else
#endif
	}

	//The send function sends data on a connected socket.
	int send(const char* buf, int len)
	{
		assert(this->isValid());
		assert(buf);

#ifdef _WIN32
		int res = ::send(s, buf, len, 0);

		if (res == SOCKET_ERROR)
		{
			checkErrorMessage(res);
		}

		return res;
#else
#endif
	}

	//The recv function receives data from a connected socket 
	//or a bound connectionless socket.
	int receive(char* buf, int len)
	{
		assert(this->isValid());
		assert(buf);

#ifdef _WIN32
		int res = ::recv(s, buf, len, 0);

		if (res == SOCKET_ERROR)
		{
			checkErrorMessage(res);
		}

		return res;
#else
#endif
	}

	int getMaxMessageSize()
	{
		assert(this->isValid());

#ifdef _WIN32
		int val = 0;
		int valSize = sizeof(val);
		int res = ::getsockopt(s, SOL_SOCKET, SO_MAX_MSG_SIZE, (char*)&val, &valSize);

		checkErrorMessage(res);

		return val;
#else
#endif
	}
};

bool socket::isInited = false; 
