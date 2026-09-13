#pragma once

// Wait set over sockets identified by caller ids. The descriptors stay
// inside this library (no fd in the public API).
// Linux: one epoll_wait. Darwin bring-up: one poll() of the whole set,
// not poll(1 fd) x N.

#include "Socket.h"

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

#if defined(__linux__)
#include <sys/epoll.h>
#endif

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

enum EventWaitBackend
{
	EVENT_WAIT_EPOLL = 0,
	EVENT_WAIT_POLL_SET
};

struct EventWait
{
	static constexpr uint32_t kWakeToken = 0xFFFFFFFFu;

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

		int p[2];
		if (pipe(p) != 0)
		{
			checkErrorMessage(1);
			return false;
		}
		wakeRead = p[0];
		wakeWrite = p[1];

		if (fcntl(wakeRead, F_SETFD, FD_CLOEXEC) != 0 ||
			fcntl(wakeWrite, F_SETFD, FD_CLOEXEC) != 0)
		{
			checkErrorMessage(1);
			close();
			return false;
		}

		int flags = fcntl(wakeRead, F_GETFL, 0);
		if (flags < 0 || fcntl(wakeRead, F_SETFL, flags | O_NONBLOCK) != 0)
		{
			checkErrorMessage(1);
			close();
			return false;
		}
		flags = fcntl(wakeWrite, F_GETFL, 0);
		if (flags < 0 || fcntl(wakeWrite, F_SETFL, flags | O_NONBLOCK) != 0)
		{
			checkErrorMessage(1);
			close();
			return false;
		}

#if defined(__linux__)
		epollFd = epoll_create1(EPOLL_CLOEXEC);
		if (epollFd < 0)
		{
			checkErrorMessage(1);
			close();
			return false;
		}
		epoll_event ev = {};
		ev.events = EPOLLIN;
		ev.data.u32 = kWakeToken;
		if (epoll_ctl(epollFd, EPOLL_CTL_ADD, wakeRead, &ev) != 0)
		{
			checkErrorMessage(1);
			close();
			return false;
		}
		kind = EVENT_WAIT_EPOLL;
#else
		{
			std::lock_guard<std::mutex> guard(mapMutex);
			pollfd w = {};
			w.fd = wakeRead;
			w.events = POLLIN;
			pollFds.push_back(w);
			pollTokens.push_back(kWakeToken);
		}
		kind = EVENT_WAIT_POLL_SET;
#endif
		return true;
	}

	void close()
	{
#if defined(__linux__)
		if (epollFd >= 0)
		{
			int res = ::close(epollFd);
			checkErrorMessage(res);
			epollFd = -1;
		}
#endif
		if (wakeRead >= 0)
		{
			int res = ::close(wakeRead);
			checkErrorMessage(res);
			wakeRead = -1;
		}
		if (wakeWrite >= 0)
		{
			int res = ::close(wakeWrite);
			checkErrorMessage(res);
			wakeWrite = -1;
		}
		std::lock_guard<std::mutex> guard(mapMutex);
		pollFds.clear();
		pollTokens.clear();
		idToFd.clear();
		fdToId.clear();
	}

	// Watch sock for readability; wait() will report id (not a descriptor).
	void add(const class socket& sock, uint32_t id)
	{
		assert(isOpen());
		assert(sock.isValid());
		assert(id != kWakeToken);
		int fd = sock.s;
		assert(SOCKET_VALID(fd));

		{
			std::lock_guard<std::mutex> guard(mapMutex);
			assert(idToFd.find(id) == idToFd.end());
			assert(fdToId.find(fd) == fdToId.end());
			idToFd[id] = fd;
			fdToId[fd] = id;
#if !defined(__linux__)
			pollfd p = {};
			p.fd = fd;
			p.events = POLLIN;
			pollFds.push_back(p);
			pollTokens.push_back(id);
#endif
		}

#if defined(__linux__)
		assert(kind == EVENT_WAIT_EPOLL);
		assert(epollFd >= 0);
		epoll_event ev = {};
		ev.events = EPOLLIN;
		ev.data.u32 = id;
		int res = epoll_ctl(epollFd, EPOLL_CTL_ADD, fd, &ev);
		if (res != 0)
		{
			int err = errno;
			checkErrorMessage(1);
			std::lock_guard<std::mutex> guard(mapMutex);
			idToFd.erase(id);
			fdToId.erase(fd);
			assert(err != EBADF && err != EEXIST);
		}
#endif
	}

	void remove(uint32_t id)
	{
		assert(isOpen());
		assert(id != kWakeToken);

		int fd = -1;
		{
			std::lock_guard<std::mutex> guard(mapMutex);
			auto it = idToFd.find(id);
			assert(it != idToFd.end());
			fd = it->second;
			idToFd.erase(it);
			fdToId.erase(fd);
#if !defined(__linux__)
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

#if defined(__linux__)
		assert(kind == EVENT_WAIT_EPOLL);
		assert(epollFd >= 0);
		assert(fd >= 0);
		int res = epoll_ctl(epollFd, EPOLL_CTL_DEL, fd, nullptr);
		if (res != 0)
		{
			int err = errno;
			if (err != ENOENT && err != EBADF)
				checkErrorMessage(1);
		}
#endif
	}

	void wakeup()
	{
		assert(isOpen());
		char x = 1;
		int res = int(::write(wakeWrite, &x, 1));
		if (res < 0 && !transientWakeErr())
			checkErrorMessage(1);
	}

	// Blocks until a watched socket is readable, wakeup, or timeoutMs (-1 = forever).
	// Ready ids are written to out[0..return). Wakeup is drained and omitted.
	int wait(uint32_t* out, int maxOut, int timeoutMs)
	{
		assert(isOpen());
		assert(out);
		assert(maxOut > 0);

#if defined(__linux__)
		if (kind == EVENT_WAIT_EPOLL)
		{
			assert(epollFd >= 0);
			epoll_event events[64];
			int n = epoll_wait(epollFd, events, 64, timeoutMs);
			if (n < 0)
			{
				if (errno == EINTR)
					return 0;
				checkErrorMessage(1);
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
				out[written++] = id;
			}
			return written;
		}
#endif

		std::vector<pollfd> snapshot;
		std::vector<uint32_t> tokenSnap;
		{
			std::lock_guard<std::mutex> guard(mapMutex);
			snapshot = pollFds;
			tokenSnap = pollTokens;
		}
		assert(!snapshot.empty());
		int n = ::poll(snapshot.data(), snapshot.size(), timeoutMs);
		if (n < 0)
		{
			if (errno == EINTR)
				return 0;
			checkErrorMessage(1);
			return -1;
		}
		if (n == 0)
			return 0;
		int written = 0;
		for (size_t i = 0; i < snapshot.size() && written < maxOut; ++i)
		{
			if (snapshot[i].revents == 0)
				continue;
			uint32_t id = tokenSnap[i];
			if (id == kWakeToken)
			{
				drainWakeup();
				continue;
			}
			out[written++] = id;
		}
		return written;
	}

private:
	static bool transientWakeErr()
	{
		if (errno == EINTR || errno == EAGAIN)
			return true;
#if defined(EWOULDBLOCK) && (EWOULDBLOCK != EAGAIN)
		if (errno == EWOULDBLOCK)
			return true;
#endif
		return false;
	}

	void drainWakeup()
	{
		assert(isOpen());
		char buf[32];
		for (;;)
		{
			int res = int(::read(wakeRead, buf, sizeof(buf)));
			if (res > 0)
				continue;
			if (res < 0 && transientWakeErr())
				break;
			if (res < 0)
				checkErrorMessage(1);
			break;
		}
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
	std::vector<pollfd> pollFds;
	std::vector<uint32_t> pollTokens;
	std::unordered_map<uint32_t, int> idToFd;
	std::unordered_map<int, uint32_t> fdToId;
};
