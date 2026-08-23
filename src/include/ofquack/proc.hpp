#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ofquack {

//! A child process, terminated when this object goes away.
//!
//! The destructor matters more than the constructor here: the browser is
//! launched in the middle of a query that can fail or be interrupted at any
//! point, and a Chrome left running with a debugging port open is both a
//! resource leak and a security one.
class ChildProcess {
public:
	//! Launches `executable` with `arguments`. Throws on failure to start.
	ChildProcess(const std::string &executable, const std::vector<std::string> &arguments);
	~ChildProcess();

	ChildProcess(const ChildProcess &) = delete;
	ChildProcess &operator=(const ChildProcess &) = delete;

	//! False once the process has exited. Does not block.
	bool IsRunning();

	//! Asks the process to stop, then insists. Called by the destructor.
	void Terminate();

private:
	struct Impl;
	std::unique_ptr<Impl> impl;
};

//! A TCP port that was free a moment ago.
//!
//! Inherently racy -- something else may take it before the browser binds --
//! so the caller retries rather than trusting it.
uint16_t FindFreeLoopbackPort();

//! True once something accepts connections on 127.0.0.1:`port`.
bool IsLoopbackPortOpen(uint16_t port);

} // namespace ofquack
