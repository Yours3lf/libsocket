#pragma once

// Wait set over sockets identified by caller ids. Descriptors stay inside
// this library. Linux: one epoll_wait. Darwin: one poll() of the whole set.
// Windows: one WSAPoll of the whole set. Not completion ports.

#include "Socket.h"

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

#if defined(__linux__)
#include <sys/epoll.h>
#include <sys/eventfd.h>
#endif

#include <cassert>
#include <cerrno>

#ifndef _WIN32
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#endif

enum EventWaitBackend
{
	EVENT_WAIT_EPOLL = 0,
	EVENT_WAIT_POLL_SET
};

#ifdef _WIN32
using WaitPollFd = WSAPOLLFD;
#else
using WaitPollFd = pollfd;
#endif

// One ready id from wait(). Wakeups are drained and omitted.
struct WaitResult
{
	uint32_t id = 0;
	bool readable = false;
	bool writable = false;
};

struct EventWait
{
	static constexpr uint32_t kWakeToken = 0xFFFFFFFFu;
	// epoll_wait / poll batch. Callers asking for more still see the rest on
	// the next wait while interest stays level-triggered.
	static constexpr int kMaxReadyBatch = 256;

	EventWait() = default;
	EventWait(const EventWait&) = delete;
	EventWait& operator=(const EventWait&) = delete;

	~EventWait()
	{
		close();
	}

	static const char* backendName(EventWaitBackend b)
	{
		return b == EVENT_WAIT_EPOLL ? "epoll" : "poll-set";
	}

	EventWaitBackend backend() const
	{
		return kind;
	}

	bool isOpen() const
	{
		return wakeRead >= 0;
	}

	bool init()
	{
		assert(!isOpen());

#if defined(__linux__)
		wakeRead = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
		if (wakeRead < 0)
		{
			reportErrno(__FILE__, __LINE__);
			return false;
		}
		wakeWrite = wakeRead;
		epollFd = epoll_create1(EPOLL_CLOEXEC);
		if (epollFd < 0)
		{
			reportErrno(__FILE__, __LINE__);
			close();
			return false;
		}
		epoll_event ev = {};
		ev.events = EPOLLIN;
		ev.data.u32 = kWakeToken;
		if (epoll_ctl(epollFd, EPOLL_CTL_ADD, wakeRead, &ev) != 0)
		{
			reportErrno(__FILE__, __LINE__);
			close();
			return false;
		}
		kind = EVENT_WAIT_EPOLL;
		return true;
#else
		if (!openWakePair())
			return false;
		{
			std::lock_guard<std::mutex> guard(mapMutex);
			WaitPollFd w = {};
			w.fd = wakeRead;
			w.events = POLLIN;
			pollFds.push_back(w);
			pollTokens.push_back(kWakeToken);
		}
		kind = EVENT_WAIT_POLL_SET;
		return true;
#endif
	}

	void close()
	{
#if defined(__linux__)
		if (epollFd >= 0)
		{
			if (::close(epollFd) != 0)
				reportErrno(__FILE__, __LINE__);
			epollFd = -1;
		}
		if (wakeRead >= 0)
		{
			if (::close(wakeRead) != 0)
				reportErrno(__FILE__, __LINE__);
			wakeRead = -1;
			wakeWrite = -1;
		}
#elif defined(_WIN32)
		if (wakeRead >= 0)
		{
			closesocket(static_cast<SOCKET>(wakeRead));
			wakeRead = -1;
		}
		if (wakeWrite >= 0)
		{
			closesocket(static_cast<SOCKET>(wakeWrite));
			wakeWrite = -1;
		}
#else
		if (wakeRead >= 0)
		{
			if (::close(wakeRead) != 0)
				reportErrno(__FILE__, __LINE__);
			wakeRead = -1;
		}
		if (wakeWrite >= 0)
		{
			if (::close(wakeWrite) != 0)
				reportErrno(__FILE__, __LINE__);
			wakeWrite = -1;
		}
#endif
		std::lock_guard<std::mutex> guard(mapMutex);
		pollFds.clear();
		pollTokens.clear();
		idToWatch.clear();
	}

	// Watches sock for readability and marks it non-blocking.
	void add(class socket& sock, uint32_t id)
	{
		addInterest(sock, id, true, false);
	}

	void addInterest(class socket& sock, uint32_t id, bool wantRead, bool wantWrite)
	{
		assert(isOpen());
		assert(sock.isValid());
		assert(id != kWakeToken);
		if (!sock.setNonBlocking(true))
			return;
		socket::socketType fd = sock.s;
		assert(socket::socketIsValid(fd));

		std::lock_guard<std::mutex> guard(mapMutex);
		assert(idToWatch.find(id) == idToWatch.end());
		Watch watch;
		watch.fd = fd;
		watch.wantRead = wantRead;
		watch.wantWrite = wantWrite;
		idToWatch[id] = watch;

#if defined(__linux__)
		epoll_event ev = {};
		ev.events = interestBits(wantRead, wantWrite);
		ev.data.u32 = id;
		if (epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev) != 0)
		{
			reportErrno(__FILE__, __LINE__);
			idToWatch.erase(id);
		}
#else
		WaitPollFd p = {};
		p.fd = fd;
		p.events = pollInterest(wantRead, wantWrite);
		pollFds.push_back(p);
		pollTokens.push_back(id);
#endif
	}

	void modify(uint32_t id, bool wantRead, bool wantWrite)
	{
		assert(isOpen());
		assert(id != kWakeToken);
		std::lock_guard<std::mutex> guard(mapMutex);
		auto it = idToWatch.find(id);
		assert(it != idToWatch.end());
		it->second.wantRead = wantRead;
		it->second.wantWrite = wantWrite;
		socket::socketType fd = it->second.fd;

#if defined(__linux__)
		epoll_event ev = {};
		ev.events = interestBits(wantRead, wantWrite);
		ev.data.u32 = id;
		if (epoll_ctl(epollFd, EPOLL_CTL_MOD, fd, &ev) != 0)
			reportErrno(__FILE__, __LINE__);
#else
		for (size_t i = 0; i < pollTokens.size(); ++i)
		{
			if (pollTokens[i] != id)
				continue;
			pollFds[i].events = pollInterest(wantRead, wantWrite);
			break;
		}
#endif
	}

	void remove(uint32_t id)
	{
		assert(isOpen());
		assert(id != kWakeToken);

		std::lock_guard<std::mutex> guard(mapMutex);
		auto it = idToWatch.find(id);
		assert(it != idToWatch.end());
		socket::socketType fd = it->second.fd;
		idToWatch.erase(it);

#if defined(__linux__)
		if (epoll_ctl(epollFd, EPOLL_CTL_DEL, fd, nullptr) != 0)
		{
			if (errno != ENOENT && errno != EBADF)
				reportErrno(__FILE__, __LINE__);
		}
#else
		(void)fd;
		for (size_t i = 0; i < pollTokens.size(); ++i)
		{
			if (pollTokens[i] != id)
				continue;
			pollFds[i] = pollFds.back();
			pollTokens[i] = pollTokens.back();
			pollFds.pop_back();
			pollTokens.pop_back();
			break;
		}
#endif
	}

	void wakeup()
	{
		assert(isOpen());
#if defined(__linux__)
		uint64_t one = 1;
		for (;;)
		{
			ssize_t res = ::write(wakeWrite, &one, sizeof(one));
			if (res >= 0)
				return;
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return;
			reportErrno(__FILE__, __LINE__);
			return;
		}
#elif defined(_WIN32)
		char x = 1;
		int res = ::send(static_cast<SOCKET>(wakeWrite), &x, 1, 0);
		if (res < 0 && !isWakeAgain(WSAGetLastError()))
			reportErrno(__FILE__, __LINE__);
#else
		char x = 1;
		for (;;)
		{
			ssize_t res = ::write(wakeWrite, &x, 1);
			if (res >= 0)
				return;
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return;
			reportErrno(__FILE__, __LINE__);
			return;
		}
#endif
	}

	// Blocks until a watched socket is ready, wakeup, or timeoutMs (-1 = forever).
	// Ready sockets are written to out[0..return). The wakeup token is omitted.
	int wait(WaitResult* out, int maxOut, int timeoutMs)
	{
		assert(isOpen());
		assert(out);
		assert(maxOut > 0);

		int batch = maxOut;
		if (batch > kMaxReadyBatch)
			batch = kMaxReadyBatch;

#if defined(__linux__)
		epoll_event events[kMaxReadyBatch];
		int n = epoll_wait(epollFd, events, batch, timeoutMs);
		if (n < 0)
		{
			if (errno == EINTR)
				return 0;
			reportErrno(__FILE__, __LINE__);
			return -1;
		}
		int written = 0;
		for (int i = 0; i < n && written < maxOut; ++i)
		{
			uint32_t id = events[i].data.u32;
			if (id == kWakeToken)
			{
				drainWakeup();
				continue;
			}
			uint32_t bits = events[i].events;
			out[written].id = id;
			out[written].readable = (bits & (EPOLLIN | EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0;
			out[written].writable = (bits & EPOLLOUT) != 0;
			++written;
		}
		return written;
#else
		std::vector<WaitPollFd> snapshot;
		std::vector<uint32_t> tokenSnap;
		{
			std::lock_guard<std::mutex> guard(mapMutex);
			snapshot = pollFds;
			tokenSnap = pollTokens;
		}
		assert(!snapshot.empty());
#ifdef _WIN32
		int n = WSAPoll(snapshot.data(), ULONG(snapshot.size()), timeoutMs);
#else
		int n = ::poll(snapshot.data(), nfds_t(snapshot.size()), timeoutMs);
#endif
		if (n < 0)
		{
#ifdef _WIN32
			if (WSAGetLastError() == WSAEINTR)
				return 0;
#else
			if (errno == EINTR)
				return 0;
#endif
			reportErrno(__FILE__, __LINE__);
			return -1;
		}
		if (n == 0)
			return 0;
		int written = 0;
		for (size_t i = 0; i < snapshot.size() && written < maxOut && written < batch; ++i)
		{
			if (snapshot[i].revents == 0)
				continue;
			uint32_t id = tokenSnap[i];
			if (id == kWakeToken)
			{
				drainWakeup();
				continue;
			}
			short bits = snapshot[i].revents;
			out[written].id = id;
			out[written].readable = (bits & (POLLIN | POLLERR | POLLHUP)) != 0;
			out[written].writable = (bits & POLLOUT) != 0;
			++written;
		}
		return written;
#endif
	}

	// Ids only. Readable and writable sockets both report. Callers that need
	// the distinction use WaitResult.
	int wait(uint32_t* out, int maxOut, int timeoutMs)
	{
		assert(out);
		assert(maxOut > 0);
		std::vector<WaitResult> batch;
		batch.resize(static_cast<size_t>(maxOut));
		int n = wait(batch.data(), maxOut, timeoutMs);
		if (n <= 0)
			return n;
		for (int i = 0; i < n; ++i)
			out[i] = batch[i].id;
		return n;
	}

private:
	struct Watch
	{
		socket::socketType fd = socket::invalidSocket;
		bool wantRead = false;
		bool wantWrite = false;
	};

	static uint32_t interestBits(bool wantRead, bool wantWrite)
	{
#if defined(__linux__)
		uint32_t bits = 0;
		if (wantRead)
			bits |= EPOLLIN;
		if (wantWrite)
			bits |= EPOLLOUT;
		return bits;
#else
		(void)wantRead;
		(void)wantWrite;
		return 0;
#endif
	}

	static short pollInterest(bool wantRead, bool wantWrite)
	{
		short bits = 0;
		if (wantRead)
			bits = short(bits | POLLIN);
		if (wantWrite)
			bits = short(bits | POLLOUT);
		return bits;
	}

	static void reportErrno(const char* file, int line)
	{
#ifndef _WIN32
		std::cerr << std::strerror(errno) << "@" << file << ":" << line << std::endl;
#else
		std::cerr << "socket error " << WSAGetLastError() << "@" << file << ":" << line << std::endl;
#endif
	}

	static bool isWakeAgain(int err)
	{
#ifdef _WIN32
		return err == WSAEWOULDBLOCK || err == WSAEINTR;
#else
		(void)err;
		return false;
#endif
	}

	bool openWakePair()
	{
#ifdef _WIN32
		SOCKET listener = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (listener == INVALID_SOCKET)
		{
			reportErrno(__FILE__, __LINE__);
			return false;
		}
		sockaddr_in addr;
		std::memset(&addr, 0, sizeof(addr));
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = 0;
		if (::bind(listener, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
			::listen(listener, 1) != 0)
		{
			reportErrno(__FILE__, __LINE__);
			closesocket(listener);
			return false;
		}
		int addrLen = sizeof(addr);
		if (::getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &addrLen) != 0)
		{
			reportErrno(__FILE__, __LINE__);
			closesocket(listener);
			return false;
		}
		SOCKET writer = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (writer == INVALID_SOCKET ||
			::connect(writer, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
		{
			reportErrno(__FILE__, __LINE__);
			if (writer != INVALID_SOCKET)
				closesocket(writer);
			closesocket(listener);
			return false;
		}
		SOCKET reader = ::accept(listener, nullptr, nullptr);
		closesocket(listener);
		if (reader == INVALID_SOCKET)
		{
			reportErrno(__FILE__, __LINE__);
			closesocket(writer);
			return false;
		}
		u_long mode = 1;
		ioctlsocket(reader, FIONBIO, &mode);
		ioctlsocket(writer, FIONBIO, &mode);
		wakeRead = int(reader);
		wakeWrite = int(writer);
		return true;
#else
		int p[2];
		if (pipe(p) != 0)
		{
			reportErrno(__FILE__, __LINE__);
			return false;
		}
		wakeRead = p[0];
		wakeWrite = p[1];
		if (fcntl(wakeRead, F_SETFD, FD_CLOEXEC) != 0 ||
			fcntl(wakeWrite, F_SETFD, FD_CLOEXEC) != 0)
		{
			reportErrno(__FILE__, __LINE__);
			close();
			return false;
		}
		int flags = fcntl(wakeRead, F_GETFL, 0);
		if (flags < 0 || fcntl(wakeRead, F_SETFL, flags | O_NONBLOCK) != 0)
		{
			reportErrno(__FILE__, __LINE__);
			close();
			return false;
		}
		flags = fcntl(wakeWrite, F_GETFL, 0);
		if (flags < 0 || fcntl(wakeWrite, F_SETFL, flags | O_NONBLOCK) != 0)
		{
			reportErrno(__FILE__, __LINE__);
			close();
			return false;
		}
		return true;
#endif
	}

	void drainWakeup()
	{
		assert(isOpen());
#if defined(__linux__)
		for (;;)
		{
			uint64_t value = 0;
			ssize_t res = ::read(wakeRead, &value, sizeof(value));
			if (res >= 0)
				return;
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				return;
			reportErrno(__FILE__, __LINE__);
			return;
		}
#elif defined(_WIN32)
		char buf[32];
		for (;;)
		{
			int res = ::recv(static_cast<SOCKET>(wakeRead), buf, int(sizeof(buf)), 0);
			if (res > 0)
				continue;
			if (res < 0 && isWakeAgain(WSAGetLastError()))
				return;
			if (res < 0)
				reportErrno(__FILE__, __LINE__);
			return;
		}
#else
		char buf[32];
		for (;;)
		{
			ssize_t res = ::read(wakeRead, buf, sizeof(buf));
			if (res > 0)
				continue;
			if (res < 0 && (errno == EINTR))
				continue;
			if (res < 0 && errno == EAGAIN)
				return;
			if (res < 0)
				reportErrno(__FILE__, __LINE__);
			return;
		}
#endif
	}

	int epollFd = -1;
	int wakeRead = -1;
	int wakeWrite = -1;
	EventWaitBackend kind =
#if defined(__linux__)
		EVENT_WAIT_EPOLL;
#else
		EVENT_WAIT_POLL_SET;
#endif

	std::mutex mapMutex;
	std::vector<WaitPollFd> pollFds;
	std::vector<uint32_t> pollTokens;
	std::unordered_map<uint32_t, Watch> idToWatch;
};
