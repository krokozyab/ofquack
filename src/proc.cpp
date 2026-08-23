#include "ofquack/proc.hpp"

#include "ofquack/errors.hpp"

#include <chrono>
#include <cstdint>
#include <cstring>
#include <thread>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
// After winsock2.h, which must come first.
#include <windows.h>
#else
#include <arpa/inet.h>
#include <csignal>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
// NOLINTNEXTLINE(cppcoreguidelines-avoid-non-const-global-variables) -- POSIX's own declaration.
extern char **environ;
#endif

namespace ofquack {

namespace {

#ifdef _WIN32
//! Windows takes one command line rather than an argument vector, so the
//! arguments have to be quoted back together following its own parsing rules.
std::string QuoteWindowsArgument(const std::string &argument) {
	if (!argument.empty() && argument.find_first_of(" \t\"") == std::string::npos) {
		return argument;
	}
	std::string quoted = "\"";
	size_t backslashes = 0;
	for (const char c : argument) {
		if (c == '\\') {
			backslashes++;
			continue;
		}
		if (c == '"') {
			// Backslashes before a quote must themselves be doubled.
			quoted.append(backslashes * 2 + 1, '\\');
			backslashes = 0;
			quoted.push_back('"');
			continue;
		}
		quoted.append(backslashes, '\\');
		backslashes = 0;
		quoted.push_back(c);
	}
	quoted.append(backslashes * 2, '\\');
	quoted.push_back('"');
	return quoted;
}
#endif

} // namespace

#ifdef _WIN32

struct ChildProcess::Impl {
	PROCESS_INFORMATION process {};
	bool started = false;
};

ChildProcess::ChildProcess(const std::string &executable, const std::vector<std::string> &arguments)
    : impl(new Impl()) {
	std::string command_line = QuoteWindowsArgument(executable);
	for (const auto &argument : arguments) {
		command_line += " " + QuoteWindowsArgument(argument);
	}

	STARTUPINFOA startup {};
	startup.cb = sizeof(startup);
	std::vector<char> mutable_command_line(command_line.begin(), command_line.end());
	mutable_command_line.push_back('\0');

	if (!CreateProcessA(nullptr, mutable_command_line.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
	                    nullptr, &startup, &impl->process)) {
		throw PermanentError("Could not start " + executable);
	}
	impl->started = true;
}

ChildProcess::~ChildProcess() {
	Terminate();
	if (impl->started) {
		CloseHandle(impl->process.hProcess);
		CloseHandle(impl->process.hThread);
	}
}

bool ChildProcess::IsRunning() {
	if (!impl->started) {
		return false;
	}
	return WaitForSingleObject(impl->process.hProcess, 0) == WAIT_TIMEOUT;
}

void ChildProcess::Terminate() {
	if (!impl->started || !IsRunning()) {
		return;
	}
	TerminateProcess(impl->process.hProcess, 0);
	WaitForSingleObject(impl->process.hProcess, 5000);
}

#else

struct ChildProcess::Impl {
	pid_t pid = -1;
	bool reaped = false;
};

ChildProcess::ChildProcess(const std::string &executable, const std::vector<std::string> &arguments)
    : impl(new Impl()) {
	std::vector<std::string> owned;
	owned.reserve(arguments.size() + 1);
	owned.push_back(executable);
	for (const auto &argument : arguments) {
		owned.push_back(argument);
	}

	std::vector<char *> argv;
	argv.reserve(owned.size() + 1);
	for (auto &value : owned) {
		// execv takes char *const[] and does not modify the strings; `owned`
		// outlives the call.
		// NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
		argv.push_back(const_cast<char *>(value.c_str()));
	}
	argv.push_back(nullptr);

	pid_t pid = -1;
	const int status = posix_spawn(&pid, executable.c_str(), nullptr, nullptr, argv.data(), environ);
	if (status != 0) {
		throw PermanentError("Could not start " + executable + ": " + std::strerror(status));
	}
	impl->pid = pid;
}

ChildProcess::~ChildProcess() {
	Terminate();
}

bool ChildProcess::IsRunning() {
	if (impl->pid < 0 || impl->reaped) {
		return false;
	}
	int status = 0;
	const pid_t result = waitpid(impl->pid, &status, WNOHANG);
	if (result == impl->pid) {
		impl->reaped = true;
		return false;
	}
	// A negative result means the child is gone and already reaped.
	return result == 0;
}

void ChildProcess::Terminate() {
	if (impl->pid < 0 || impl->reaped) {
		return;
	}
	kill(impl->pid, SIGTERM);
	// Give it a moment to close down cleanly; Chrome writes its profile on exit.
	for (int waited_ms = 0; waited_ms < 5000; waited_ms += 50) {
		if (!IsRunning()) {
			return;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	kill(impl->pid, SIGKILL);
	int status = 0;
	waitpid(impl->pid, &status, 0);
	impl->reaped = true;
}

#endif

uint16_t FindFreeLoopbackPort() {
#ifdef _WIN32
	WSADATA winsock_data;
	WSAStartup(MAKEWORD(2, 2), &winsock_data);
	using socket_t = SOCKET;
	const socket_t invalid = INVALID_SOCKET;
#else
	using socket_t = int;
	const socket_t invalid = -1;
#endif

	socket_t handle = socket(AF_INET, SOCK_STREAM, 0);
	if (handle == invalid) {
		throw PermanentError("Could not create a socket to pick a debugging port");
	}

	sockaddr_in address {};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = 0; // let the kernel choose

	uint16_t port = 0;
	if (bind(handle, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0) {
		socklen_t length = sizeof(address);
		if (getsockname(handle, reinterpret_cast<sockaddr *>(&address), &length) == 0) {
			port = ntohs(address.sin_port);
		}
	}
#ifdef _WIN32
	closesocket(handle);
#else
	close(handle);
#endif

	if (port == 0) {
		throw PermanentError("Could not find a free port for the browser debugging connection");
	}
	return port;
}

bool IsLoopbackPortOpen(uint16_t port) {
#ifdef _WIN32
	using socket_t = SOCKET;
	const socket_t invalid = INVALID_SOCKET;
#else
	using socket_t = int;
	const socket_t invalid = -1;
#endif

	socket_t handle = socket(AF_INET, SOCK_STREAM, 0);
	if (handle == invalid) {
		return false;
	}
	sockaddr_in address {};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	address.sin_port = htons(port);

	const bool connected = connect(handle, reinterpret_cast<sockaddr *>(&address), sizeof(address)) == 0;
#ifdef _WIN32
	closesocket(handle);
#else
	close(handle);
#endif
	return connected;
}

} // namespace ofquack
