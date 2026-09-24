#pragma once

#include <string>
#include <iostream>
#include <cstdint>
#include <cstring>
#include <utility>
#include <cassert>

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
#include <fcntl.h>
#include <errno.h>
#endif

// https://beej.us/guide/bgnet/html/split/

struct EventWait;

// Header-only TCP/UDP socket. Descriptors stay inside this type.
// kPeerClosed: the peer shut the stream down (recv 0 or EPIPE).
// kWouldBlock: non-blocking socket, no bytes moved.
// A positive return is bytes moved. A short positive count is progress, not failure.
class socket
{
public:
	static constexpr int kPeerClosed = -2;
	static constexpr int kWouldBlock = -4;
	// POSIX has no SO_MAX_MSG_SIZE. UDP datagrams larger than this are rejected
	// by the kernel on a normal path MTU; callers can still getsockopt on Windows.
	static constexpr int kUdpMaxMessageSize = 65535;

	// First member must stay the descriptor. TLSsession reads it with
	// SSL_set_fd(ssl, *(int*)&socketObject).
#ifdef _WIN32
	typedef uint64_t socketType;
	static constexpr socketType invalidSocket = static_cast<socketType>(INVALID_SOCKET);
#else
	typedef int32_t socketType;
	static constexpr socketType invalidSocket = -1;
#endif

	inline static bool isInited = false;

	static int init()
	{
#ifdef _WIN32
		WSADATA wsaData;
		int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
		if (res == 0)
			isInited = true;
		else
			reportLastError(__FILE__, __LINE__);
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
			if (WSACleanup() != 0)
				reportLastError(__FILE__, __LINE__);
		}
#else
		isInited = false;
#endif
	}

	socket()
		: s(invalidSocket)
	{
		assert(isInited);
	}

	explicit socket(socketType ss)
		: s(ss)
	{
		assert(isInited);
	}

	socket(socket&& other) noexcept
		: s(other.s)
		, nonBlocking(other.nonBlocking)
		, connected(other.connected)
	{
		other.s = invalidSocket;
		other.nonBlocking = false;
		other.connected = false;
	}

	socket& operator=(socket&& other) noexcept
	{
		if (this != &other)
		{
			close(false);
			s = other.s;
			nonBlocking = other.nonBlocking;
			connected = other.connected;
			other.s = invalidSocket;
			other.nonBlocking = false;
			other.connected = false;
		}
		return *this;
	}

	socket& operator=(const socket&) = delete;
	socket(const socket&) = delete;

	~socket()
	{
		close(connected);
	}

	bool isValid() const
	{
		return socketIsValid(s);
	}

	bool isNonBlocking() const
	{
		return nonBlocking;
	}

	bool setNonBlocking(bool enabled)
	{
		assert(isValid());
#ifdef _WIN32
		u_long mode = enabled ? 1 : 0;
		if (ioctlsocket(static_cast<SOCKET>(s), FIONBIO, &mode) != 0)
		{
			reportLastError(__FILE__, __LINE__);
			return false;
		}
#else
		int flags = fcntl(s, F_GETFL, 0);
		if (flags < 0)
		{
			reportLastError(__FILE__, __LINE__);
			return false;
		}
		if (enabled)
			flags |= O_NONBLOCK;
		else
			flags &= ~O_NONBLOCK;
		if (fcntl(s, F_SETFL, flags) != 0)
		{
			reportLastError(__FILE__, __LINE__);
			return false;
		}
#endif
		nonBlocking = enabled;
		return true;
	}

	// Shutdown only when this socket completed connect or accept.
	// Listening and unbound sockets are closed without a shutdown log.
	void close(bool clean = true)
	{
		if (!isValid())
			return;

		// clean close also shuts down listeners. That unblocks a thread
		// sitting in accept(). ENOTCONN/EINVAL is normal for a socket that
		// was never connected; the destructor skips this unless connected.
		if (clean)
		{
			int status = ::shutdown(s,
#ifdef _WIN32
				SD_BOTH
#else
				SHUT_RDWR
#endif
			);
			int err = lastErrorCode();
			if (status != 0 && !isNotConnected(err) && err != EINVAL)
				reportLastError(__FILE__, __LINE__);
		}

#ifdef _WIN32
		if (closesocket(static_cast<SOCKET>(s)) != 0)
			reportLastError(__FILE__, __LINE__);
#else
		if (::close(s) != 0)
			reportLastError(__FILE__, __LINE__);
#endif
		s = invalidSocket;
		connected = false;
		nonBlocking = false;
	}

	uint16_t localPort() const
	{
		assert(isValid());
		sockaddr_storage addr;
		std::memset(&addr, 0, sizeof(addr));
		socklen_t len = sizeof(addr);
		if (::getsockname(s, reinterpret_cast<sockaddr*>(&addr), &len) != 0)
		{
			reportLastError(__FILE__, __LINE__);
			return 0;
		}
		return portOf(reinterpret_cast<sockaddr*>(&addr));
	}

	bool operator==(const socket& other) const
	{
		return s == other.s;
	}

	int connect(const std::string& address, uint16_t port, bool udp = false, bool ipv6 = false)
	{
		sockaddr_storage addr;
		socklen_t addrLen = 0;
		int family = 0;
		int type = 0;
		int proto = 0;
		if (!resolve(address, port, udp, ipv6, false, addr, addrLen, family, type, proto))
			return -1;

		create(family, type, proto);
		if (!isValid())
			return -1;

		int res = ::connect(s, reinterpret_cast<sockaddr*>(&addr), addrLen);
		if (res != 0)
		{
			reportLastError(__FILE__, __LINE__);
			return -1;
		}
		connected = true;
		return 0;
	}

	int bind(const std::string& address, uint16_t port, bool udp = false, bool ipv6 = false, bool reuseAddress = false, bool reusePort = false)
	{
		sockaddr_storage addr;
		socklen_t addrLen = 0;
		int family = 0;
		int type = 0;
		int proto = 0;
		if (!resolve(address, port, udp, ipv6, true, addr, addrLen, family, type, proto))
			return -1;

		create(family, type, proto);
		if (!isValid())
			return -1;

		int reuse = reuseAddress ? 1 : 0;
		if (!setIntOption(SOL_SOCKET, SO_REUSEADDR, reuse))
			return -1;
#ifdef SO_REUSEPORT
		int reuseP = reusePort ? 1 : 0;
		if (!setIntOption(SOL_SOCKET, SO_REUSEPORT, reuseP))
			return -1;
#else
		(void)reusePort;
#endif

		if (::bind(s, reinterpret_cast<sockaddr*>(&addr), addrLen) != 0)
		{
			reportLastError(__FILE__, __LINE__);
			return -1;
		}
		return 0;
	}

	// Default 4096 rather than glibc's SOMAXCONN (128): the kernel still caps
	// at net.core.somaxconn, so a raised sysctl is not silently truncated.
	int listen(int backlog = 4096)
	{
		assert(isValid());
		if (::listen(s, backlog) != 0)
		{
			reportLastError(__FILE__, __LINE__);
			return -1;
		}
		return 0;
	}

	socket accept(std::string* addrStr)
	{
		assert(isValid());
		sockaddr_storage addr;
		std::memset(&addr, 0, sizeof(addr));
		socklen_t len = sizeof(addr);
#ifdef __linux__
		socketType accepted = ::accept4(s, reinterpret_cast<sockaddr*>(&addr), &len, SOCK_CLOEXEC);
#else
		socketType accepted = ::accept(s, reinterpret_cast<sockaddr*>(&addr), &len);
#endif
		if (!socketIsValid(accepted))
		{
			if (!isWouldBlock(lastErrorCode()))
				reportLastError(__FILE__, __LINE__);
			return socket(invalidSocket);
		}
#ifndef _WIN32
#ifndef __linux__
		if (fcntl(accepted, F_SETFD, FD_CLOEXEC) != 0)
			reportLastError(__FILE__, __LINE__);
#endif
#endif
		if (addrStr)
			*addrStr = formatAddress(reinterpret_cast<sockaddr*>(&addr));
		socket out(accepted);
		out.connected = true;
		return out;
	}

	// Blocking: all of len, or an error. Non-blocking: bytes accepted by the
	// kernel, or kWouldBlock when none were moved.
	int send(const char* buf, int len)
	{
		assert(isValid());
		assert(buf || len == 0);
		if (len == 0)
			return 0;

		int flags = 0;
#ifdef MSG_NOSIGNAL
		flags = MSG_NOSIGNAL;
#endif
		int sent = 0;
		while (sent < len)
		{
			int res = ::send(s, buf + sent, size_t(len - sent), flags);
			if (res < 0)
			{
				int err = lastErrorCode();
				if (isInterrupted(err))
					continue;
				if (isWouldBlock(err))
					return sent > 0 ? sent : kWouldBlock;
				if (isPipe(err))
					return kPeerClosed;
				reportLastError(__FILE__, __LINE__);
				return sent > 0 ? sent : -1;
			}
			if (res == 0)
				break;
			sent += res;
			if (nonBlocking)
			{
				// One more iteration only happens if the kernel still accepts
				// bytes. Stop once a call would block (handled above).
			}
		}
		return sent;
	}

	int sendto(const char* buf, int len, const std::string& address, uint16_t port, bool ipv6 = false)
	{
		assert(isValid());
		assert(buf || len == 0);
		sockaddr_storage addr;
		socklen_t addrLen = 0;
		int family = 0;
		int type = 0;
		int proto = 0;
		if (!resolve(address, port, true, ipv6, false, addr, addrLen, family, type, proto))
			return -1;

		int flags = 0;
#ifdef MSG_NOSIGNAL
		flags = MSG_NOSIGNAL;
#endif
		for (;;)
		{
			int res = ::sendto(s, buf, size_t(len), flags, reinterpret_cast<sockaddr*>(&addr), addrLen);
			if (res < 0)
			{
				int err = lastErrorCode();
				if (isInterrupted(err))
					continue;
				if (isWouldBlock(err))
					return kWouldBlock;
				reportLastError(__FILE__, __LINE__);
				return -1;
			}
			return res;
		}
	}

	// 1 readable, 0 timeout, -1 error. Used by the HTTP upgrade so a partial
	// header does not spin or block forever.
	int waitReadable(int timeoutMs)
	{
		assert(isValid());
#ifdef _WIN32
		WSAPOLLFD fds;
		fds.fd = static_cast<SOCKET>(s);
		fds.events = POLLIN;
		fds.revents = 0;
		int res = WSAPoll(&fds, 1, timeoutMs);
		if (res < 0)
		{
			if (WSAGetLastError() == WSAEINTR)
				return 0;
			reportLastError(__FILE__, __LINE__);
			return -1;
		}
		if (res == 0)
			return 0;
		return (fds.revents & (POLLIN | POLLHUP | POLLERR)) != 0 ? 1 : 0;
#else
		pollfd fds;
		fds.fd = s;
		fds.events = POLLIN;
		fds.revents = 0;
		for (;;)
		{
			int res = ::poll(&fds, 1, timeoutMs);
			if (res < 0 && errno == EINTR)
				continue;
			if (res < 0)
			{
				reportLastError(__FILE__, __LINE__);
				return -1;
			}
			if (res == 0)
				return 0;
			return (fds.revents & (POLLIN | POLLHUP | POLLERR)) != 0 ? 1 : 0;
		}
#endif
	}

	bool receivedAnyBytes()
	{
		assert(isValid());
#ifdef _WIN32
		WSAPOLLFD fds;
		fds.fd = static_cast<SOCKET>(s);
		fds.events = POLLIN;
		fds.revents = 0;
		int res = WSAPoll(&fds, 1, 0);
		if (res < 0)
		{
			reportLastError(__FILE__, __LINE__);
			return false;
		}
		return (fds.revents & (POLLIN | POLLHUP | POLLERR)) != 0;
#else
		pollfd fds;
		fds.fd = s;
		fds.events = POLLIN;
		fds.revents = 0;
		for (;;)
		{
			int res = ::poll(&fds, 1, 0);
			if (res < 0 && errno == EINTR)
				continue;
			if (res < 0)
			{
				reportLastError(__FILE__, __LINE__);
				return false;
			}
			break;
		}
		return (fds.revents & (POLLIN | POLLHUP | POLLERR)) != 0;
#endif
	}

	// singleRecv: one successful recv, then return (short reads included).
	// Otherwise blocking sockets fill len. Non-blocking sockets stop on would-block.
	int receive(char* buf, int len, bool singleRecv = false)
	{
		assert(isValid());
		assert(buf || len == 0);
		if (len == 0)
			return 0;

		int got = 0;
		while (got < len)
		{
			int res = ::recv(s, buf + got, size_t(len - got), 0);
			if (res == 0)
				return got > 0 ? got : kPeerClosed;
			if (res < 0)
			{
				int err = lastErrorCode();
				if (isInterrupted(err))
					continue;
				if (isWouldBlock(err))
					return got > 0 ? got : kWouldBlock;
				reportLastError(__FILE__, __LINE__);
				return got > 0 ? got : -1;
			}
			got += res;
			if (singleRecv || nonBlocking)
				break;
		}
		return got;
	}

	int recvfrom(char* buf, int len, std::string* addrStr)
	{
		assert(isValid());
		assert(buf || len == 0);
		sockaddr_storage addr;
		std::memset(&addr, 0, sizeof(addr));
		socklen_t addrLen = sizeof(addr);
		for (;;)
		{
			int res = ::recvfrom(s, buf, size_t(len), 0, reinterpret_cast<sockaddr*>(&addr), &addrLen);
			if (res < 0)
			{
				int err = lastErrorCode();
				if (isInterrupted(err))
					continue;
				if (isWouldBlock(err))
					return kWouldBlock;
				reportLastError(__FILE__, __LINE__);
				return -1;
			}
			if (addrStr)
				*addrStr = formatAddress(reinterpret_cast<sockaddr*>(&addr));
			return res;
		}
	}

	int getMaxMessageSize()
	{
		assert(isValid());
#ifdef _WIN32
		int val = 0;
		int valSize = sizeof(val);
		if (::getsockopt(s, SOL_SOCKET, SO_MAX_MSG_SIZE, reinterpret_cast<char*>(&val), &valSize) != 0)
		{
			reportLastError(__FILE__, __LINE__);
			return kUdpMaxMessageSize;
		}
		return val;
#else
		return kUdpMaxMessageSize;
#endif
	}

private:
	socketType s = invalidSocket;
	bool nonBlocking = false;
	bool connected = false;

	friend struct EventWait;

	static bool socketIsValid(socketType fd)
	{
#ifdef _WIN32
		return fd != invalidSocket;
#else
		return fd >= 0;
#endif
	}

	static int lastErrorCode()
	{
#ifdef _WIN32
		return WSAGetLastError();
#else
		return errno;
#endif
	}

	static bool isInterrupted(int err)
	{
#ifdef _WIN32
		return err == WSAEINTR;
#else
		return err == EINTR;
#endif
	}

	static bool isWouldBlock(int err)
	{
#ifdef _WIN32
		return err == WSAEWOULDBLOCK;
#else
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
		if (err == EWOULDBLOCK)
			return true;
#endif
		return err == EAGAIN;
#endif
	}

	static bool isPipe(int err)
	{
#ifdef _WIN32
		return err == WSAECONNRESET || err == WSAECONNABORTED;
#else
		return err == EPIPE || err == ECONNRESET;
#endif
	}

	static bool isNotConnected(int err)
	{
#ifdef _WIN32
		return err == WSAENOTCONN;
#else
		return err == ENOTCONN;
#endif
	}

	static void reportLastError(const char* file, int line)
	{
#ifdef _WIN32
		int error = WSAGetLastError();
		char* message = nullptr;
		FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			nullptr, error,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
			reinterpret_cast<LPSTR>(&message), 0, nullptr);
		if (message)
		{
			std::cerr << message << "@" << file << ":" << line << std::endl;
			LocalFree(message);
		}
		else
		{
			std::cerr << "socket error " << error << "@" << file << ":" << line << std::endl;
		}
#else
		std::cerr << std::strerror(errno) << "@" << file << ":" << line << std::endl;
#endif
	}

	static uint16_t portOf(const sockaddr* addr)
	{
		if (!addr)
			return 0;
		if (addr->sa_family == AF_INET)
			return ntohs(reinterpret_cast<const sockaddr_in*>(addr)->sin_port);
		if (addr->sa_family == AF_INET6)
			return ntohs(reinterpret_cast<const sockaddr_in6*>(addr)->sin6_port);
		return 0;
	}

	static std::string formatAddress(const sockaddr* addr)
	{
		if (!addr)
			return {};
		char host[INET6_ADDRSTRLEN] = {};
		uint16_t port = portOf(addr);
		const char* family = "unspec";
		if (addr->sa_family == AF_INET)
		{
			family = "ipv4";
			inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(addr)->sin_addr, host, sizeof(host));
		}
		else if (addr->sa_family == AF_INET6)
		{
			family = "ipv6";
			inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(addr)->sin6_addr, host, sizeof(host));
		}
		else
		{
			return std::string("AF ") + std::to_string(addr->sa_family);
		}
		return std::string("AF ") + family + " " + host + ":" + std::to_string(port);
	}

	static bool resolve(const std::string& address, uint16_t port, bool udp, bool ipv6, bool passive,
		sockaddr_storage& outAddr, socklen_t& outLen, int& family, int& type, int& proto)
	{
		family = ipv6 ? AF_INET6 : AF_INET;
		type = udp ? SOCK_DGRAM : SOCK_STREAM;
		proto = 0;
		outLen = 0;
		std::memset(&outAddr, 0, sizeof(outAddr));

		addrinfo hints = {};
		hints.ai_family = family;
		hints.ai_socktype = type;
		if (passive && address.empty())
			hints.ai_flags = AI_PASSIVE;

		const std::string portStr = std::to_string(port);
		addrinfo* info = nullptr;
		int res = getaddrinfo(address.empty() ? nullptr : address.c_str(), portStr.c_str(), &hints, &info);
		if (res != 0)
		{
			std::cerr << gai_strerror(res) << std::endl;
			return false;
		}
		if (!info || !info->ai_addr || info->ai_addrlen > sizeof(sockaddr_storage))
		{
			std::cerr << "Convert address couldn't find address matching family" << std::endl;
			freeaddrinfo(info);
			return false;
		}

		std::memcpy(&outAddr, info->ai_addr, info->ai_addrlen);
		outLen = socklen_t(info->ai_addrlen);
		family = info->ai_family;
		type = info->ai_socktype;
		proto = info->ai_protocol;
		freeaddrinfo(info);
		return true;
	}

	void create(int af, int type, int proto)
	{
		if (isValid())
			return;
#ifdef __linux__
		s = ::socket(af, type | SOCK_CLOEXEC, proto);
#else
		s = ::socket(af, type, proto);
#endif
		if (!socketIsValid(s))
		{
			reportLastError(__FILE__, __LINE__);
			s = invalidSocket;
			return;
		}
#ifndef _WIN32
#ifndef __linux__
		if (fcntl(s, F_SETFD, FD_CLOEXEC) != 0)
			reportLastError(__FILE__, __LINE__);
#endif
#endif
	}

	bool setIntOption(int level, int name, int value)
	{
		const char* bytes = reinterpret_cast<const char*>(&value);
		if (::setsockopt(s, level, name, bytes, sizeof(value)) != 0)
		{
			reportLastError(__FILE__, __LINE__);
			return false;
		}
		return true;
	}
};
