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
#include <sys/poll.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#endif

//https://beej.us/guide/bgnet/html/split/

class socket
{
private:
	static bool isInited;

#ifdef _WIN32
	typedef uint64_t socketType;
#define SOCKET_VALID(x) (x != INVALID_SOCKET)
	const static socketType invalidSocket = INVALID_SOCKET;
#else
	typedef int32_t socketType;
#define SOCKET_VALID(x) (x >= 0)
	const static socketType invalidSocket = -1;
#endif

    socketType s = invalidSocket;

#ifndef _WIN32
#define SOCKET_ERROR SO_ERROR
#endif

    const int socketError = SOCKET_ERROR;

#define checkErrorMessage(c) _checkErrorMessage(c, __FILE__, __LINE__)
    static void _checkErrorMessage(int code, const char* file, int line)
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
        std::cerr << std::string(message) << "@" << file << ":" << line << std::endl;
        LocalFree(message);
#else
        std::cerr << std::string(strerror(errno)) << "@" << file << ":" << line << std::endl;
#endif
    }

	void convertAddress(const std::string& address, uint16_t port, int type, int family, struct sockaddr* outAddr, int* proto)
	{
		assert(outAddr);
        assert(type);
        assert(proto);

		addrinfo* addressInfo = 0;
        addrinfo hints = {};
        hints.ai_family = family;
        hints.ai_socktype = type;
        std::string portStr = std::to_string(port);

        if (address.empty())
        {    
            hints.ai_flags = AI_PASSIVE;    
        }

        int res = getaddrinfo(address.empty() ? 0 : address.data(), portStr.c_str(), &hints, &addressInfo);

        if (res)
        {
            std::cerr << gai_strerror(res) << std::endl;
        }

        bool found = false;
		int i = 0;
		for (addrinfo* ptr = addressInfo; ptr != 0; ptr = ptr->ai_next)
		{
			/**
			std::cout << "Getaddrinfo response " << i++ << std::endl;
			std::cout << "Flags " << ptr->ai_flags << std::endl;
            std::cout << "Requested Family: " << family << std::endl;
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
			/**/

			if (family == ptr->ai_family && type == ptr->ai_socktype)
			{
                found = true;
				memcpy(outAddr, ptr->ai_addr, ptr->ai_addrlen);
                *proto = ptr->ai_protocol;
				break;
			}
		}

        if (!found)
        {
            std::cerr << "Convert address couldn't find address matching family" << std::endl;
        }

		freeaddrinfo(addressInfo);
	}

	//The socket function creates a socket that is bound 
	//to a specific transport service provider.
    void create(int af, int type, int proto)
	{
		if (this->isValid())
			return;

		s = ::socket(af, type, proto);

		if (s == invalidSocket)
		{
			checkErrorMessage(1);
		}
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

		s = invalidSocket;
	}

	socket(socket&& ss)
	{
		s = ss.s;
		ss.s = invalidSocket;
	}

	socket& operator=(socket&& ss)
	{
		if (this != &ss)
		{
			s = ss.s;
			ss.s = invalidSocket;
		}

		return *this;
	}

	socket& operator=(const socket&) = delete;
	socket(const socket&) = delete;

	~socket()
	{
		close();
	}

	socket() : s(invalidSocket)
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

    bool operator==(const class socket& ss) const
    {
        return s == ss.s;
    }

	//The connect function establishes a connection to a specified socket.
	int connect(const std::string& address, uint16_t port, bool udp = false, bool ipv6 = false)
	{
        int family = ipv6 ? AF_INET6 : AF_INET, 
            type = udp ? SOCK_DGRAM : SOCK_STREAM, 
            proto;
		struct sockaddr sockaddr;
        convertAddress(address, port, type, family, &sockaddr, &proto);

        create(family, type, proto);
        assert(this->isValid());

		int res = ::connect(s, &sockaddr, sizeof(sockaddr));

		checkErrorMessage(res);

		return res;
	}

	//The bind function associates a local address with a socket.
	int bind(const std::string& address, uint16_t port, bool udp = false, bool ipv6 = false, bool reuseAddress = false, bool reusePort = false)
	{
        int family = ipv6 ? AF_INET6 : AF_INET, 
            type = udp ? SOCK_DGRAM : SOCK_STREAM, 
            proto;
		struct sockaddr sockaddr;
		convertAddress(address, port, type, family, &sockaddr, &proto);

        create(family, type, proto);
        assert(this->isValid());

        setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char*) & reuseAddress, sizeof(reuseAddress));
        setsockopt(s, SOL_SOCKET, SO_REUSEPORT, (const char*) & reusePort, sizeof(reusePort));

		int res = ::bind(s, &sockaddr, sizeof(sockaddr));

		checkErrorMessage(res);

		return res;
	}

	//The listen function places a socket in a state 
	//in which it is listening for an incoming connection.
	int listen()
	{
		assert(this->isValid());

		int res = ::listen(s, SOMAXCONN);

		checkErrorMessage(res);

		return res;
	}

	socket accept(std::string* addrStr)
	{
		assert(this->isValid());

        struct sockaddr_in addr;
        int len = sizeof(addr);
		socketType ss = ::accept(s, (struct sockaddr*) & addr, (socklen_t*) & len);

        if (len == sizeof(addr) && addrStr && SOCKET_VALID(ss))
        {
            addrStr->reserve(3 + 6 + 16 + 6 + 1);
            addrStr->append("AF ");
            switch (addr.sin_family)
            {
            case AF_UNSPEC:
            {
                addrStr->append("unspec");
                break;
            }
            case AF_INET:
            {
                addrStr->append("ipv4");
                break;
            }
            case AF_INET6:
            {
                addrStr->append("ipv6");
                break;
            }
            default:
            {
                addrStr->append(std::to_string(addr.sin_family));
                break;
            }
            }

            if (char* s = inet_ntoa(addr.sin_addr))
            {
                addrStr->append(" ");
                addrStr->append(s);
            }

            addrStr->append(":");
            addrStr->append(std::to_string(addr.sin_port));
        }

		if (!SOCKET_VALID(ss))
		{
			checkErrorMessage(1);
		}

		return socket(ss);
	}

	//The send function sends data on a connected socket.
	int send(const char* buf, int len)
	{
		assert(this->isValid());
		assert(buf);

        //send would raise SIGPIPE if the other side disconnected
        //that would terminate our program
        int flags = MSG_NOSIGNAL;

        int bytesSent = 0;
        while (bytesSent < len)
        {
            int res = ::send(s, buf + bytesSent, len - bytesSent, flags);

            if (res == socketError)
            {
                //check if the other side closed the connection
                if (errno == EPIPE)
                {
                    return -2;
                }

                checkErrorMessage(res);
                return res;
            }

            bytesSent += res;
        }

        assert(bytesSent == len);

		return bytesSent;
	}

    bool receivedAnyBytes()
    {
        assert(this->isValid());

        struct pollfd fds;
        fds.fd = s;
        fds.events = POLLIN;

        ::poll(&fds, 1, 0);

        return fds.revents & fds.events;
    }

	//The recv function receives data from a connected socket 
	//or a bound connectionless socket.
	int receive(char* buf, int len, bool singleRecv = false)
	{
		assert(this->isValid());
		assert(buf);

        int bytesReceived = 0;
        while (bytesReceived < len)
        {
            int res = ::recv(s, buf + bytesReceived, len - bytesReceived, 0);

            //check if the other side closed the connection
            if (res == 0)
            {
                return -2;
            }
            else if (res == socketError)
            {
                checkErrorMessage(res);
                return res;
            }

            bytesReceived += res;

            if (singleRecv)
            {
                break;
            }
        }

        return bytesReceived;
	}

	int getMaxMessageSize()
	{
		assert(this->isValid());

		int val = 0;
		int valSize = sizeof(val);
#ifdef _WIN32
		int res = ::getsockopt(s, SOL_SOCKET, SO_MAX_MSG_SIZE, (char*)&val, &valSize);

		checkErrorMessage(res);
#else
		val = 65535;
#endif

		return val;
	}
};

bool socket::isInited = false; 
