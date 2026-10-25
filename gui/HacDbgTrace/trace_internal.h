#pragma once

#include "hacdbg_trace_api.h"
#include "trace_view.h"

#include <Windows.h>

#include <d3d11.h>
#include <dxgi.h>
#include <wrl/client.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <thread>

constexpr UINT trace_wake_message = WM_APP + 0x41;
constexpr UINT trace_stop_message = WM_APP + 0x42;

struct trace_window_state
{
	HACDBG_TRACE_THEME theme = {};
	uint32_t dpi = 96;
	uint32_t width = 1;
	uint32_t height = 1;
	uint32_t visible = 1;
};

HACDBG_TRACE_THEME trace_default_theme();

class trace_snapshot_mailbox
{
public:
	void publish(const HACDBG_TRACE_SNAPSHOT& snapshot);
	bool copy_latest(HACDBG_TRACE_SNAPSHOT& snapshot_out, uint64_t& generation_out, uint64_t seen_generation) const;
	bool copy_current(HACDBG_TRACE_SNAPSHOT& snapshot_out) const;

private:
	std::mutex publish_mutex_ = {};
	mutable std::shared_mutex mutex_ = {};
	std::array<HACDBG_TRACE_SNAPSHOT, 2> buffers_ = {};
	std::atomic<uint32_t> active_ = 0;
	uint64_t generation_ = 0;
};

class trace_renderer
{
public:
	trace_renderer() = default;
	trace_renderer(const trace_renderer&) = delete;
	trace_renderer& operator=(const trace_renderer&) = delete;

	bool initialize(HWND window, uint32_t width, uint32_t height);
	void shutdown();
	bool resize(uint32_t width, uint32_t height);
	bool render(const HACDBG_TRACE_THEME& theme);
	ID3D11Device* device() const;
	ID3D11DeviceContext* context() const;
	uint32_t width() const;
	uint32_t height() const;

private:
	bool create_target();
	void release_target();

	Microsoft::WRL::ComPtr<ID3D11Device> device_ = {};
	Microsoft::WRL::ComPtr<ID3D11DeviceContext> context_ = {};
	Microsoft::WRL::ComPtr<IDXGISwapChain> swap_chain_ = {};
	Microsoft::WRL::ComPtr<ID3D11RenderTargetView> target_ = {};
	uint32_t width_ = 0;
	uint32_t height_ = 0;
};

struct HACDBG_TRACE
{
	HACDBG_TRACE(HWND host_window, HINSTANCE module, const HACDBG_TRACE_THEME* initial_theme);

	HWND host = nullptr;
	HINSTANCE instance = nullptr;
	std::atomic<HWND> child = nullptr;
	std::thread render_thread = {};
	std::atomic<DWORD> render_thread_id = 0;
	std::atomic<bool> stopping = false;
	std::atomic<uint32_t> last_error = 0;

	std::mutex command_mutex = {};
	trace_window_state window = {};
	uint64_t command_serial = 1;

	std::mutex action_mutex = {};
	HACDBG_TRACE_ACTION_CALLBACK action_callback = nullptr;
	void* action_context = nullptr;
	bool failure_pending = false;
	bool failure_reported = false;

	trace_snapshot_mailbox snapshots = {};
	trace_renderer renderer = {};
	trace_view view;
};

uint32_t trace_hresult_code(HRESULT result);
void trace_notify(HACDBG_TRACE* trace);
void trace_invoke_action(HACDBG_TRACE* trace, uint32_t action);
void trace_report_failure(HACDBG_TRACE* trace, uint32_t error);
bool trace_host_start(HACDBG_TRACE* trace);
void trace_host_detach(HACDBG_TRACE* trace);
