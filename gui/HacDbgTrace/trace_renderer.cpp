/**
 * @file trace_renderer.cpp
 * @brief Direct3D 11 swap-chain ownership for the embedded trace window.
 *
 * @author HacDbg
 */

#include "trace_internal.h"

#include <imgui_impl_dx11.h>

#include <algorithm>

namespace
{
	float color_channel(const uint32_t color, const uint32_t shift)
	{
		return static_cast<float>((color >> shift) & 0xFFu) / 255.0f;
	}
}

bool trace_renderer::initialize(const HWND window, const uint32_t width, const uint32_t height)
{
	width_ = (std::max)(width, 1u);
	height_ = (std::max)(height, 1u);

	DXGI_SWAP_CHAIN_DESC description = {};
	description.BufferDesc.Width = width_;
	description.BufferDesc.Height = height_;
	description.BufferDesc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
	description.SampleDesc.Count = 1;
	description.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
	description.BufferCount = 2;
	description.OutputWindow = window;
	description.Windowed = TRUE;
	description.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
	description.Flags = 0;

	const D3D_FEATURE_LEVEL levels[] = {
		D3D_FEATURE_LEVEL_11_0,
		D3D_FEATURE_LEVEL_10_1,
		D3D_FEATURE_LEVEL_10_0
	};

	HRESULT result = E_FAIL;

	for (const D3D_DRIVER_TYPE driver : {D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP})
	{
		D3D_FEATURE_LEVEL selected_level = D3D_FEATURE_LEVEL_10_0;
		result = D3D11CreateDeviceAndSwapChain(
			nullptr,
			driver,
			nullptr,
			D3D11_CREATE_DEVICE_BGRA_SUPPORT,
			levels,
			static_cast<UINT>(std::size(levels)),
			D3D11_SDK_VERSION,
			&description,
			swap_chain_.ReleaseAndGetAddressOf(),
			device_.ReleaseAndGetAddressOf(),
			&selected_level,
			context_.ReleaseAndGetAddressOf());

		if (SUCCEEDED(result))
		{
			break;
		}
	}

	if (FAILED(result) || device_ == nullptr || context_ == nullptr || swap_chain_ == nullptr)
	{
		shutdown();
		return false;
	}

	if (create_target() == false)
	{
		shutdown();
		return false;
	}

	return true;
}

void trace_renderer::shutdown()
{
	release_target();
	swap_chain_.Reset();
	context_.Reset();
	device_.Reset();
	width_ = 0;
	height_ = 0;
}

bool trace_renderer::resize(const uint32_t width, const uint32_t height)
{
	const uint32_t next_width = (std::max)(width, 1u);
	const uint32_t next_height = (std::max)(height, 1u);

	if (swap_chain_ == nullptr || context_ == nullptr)
	{
		return false;
	}

	if (next_width == width_ && next_height == height_)
	{
		return true;
	}

	context_->OMSetRenderTargets(0, nullptr, nullptr);
	release_target();

	const HRESULT result = swap_chain_->ResizeBuffers(0, next_width, next_height, DXGI_FORMAT_UNKNOWN, 0);

	if (FAILED(result))
	{
		return false;
	}

	width_ = next_width;
	height_ = next_height;

	return create_target();
}

bool trace_renderer::render(const HACDBG_TRACE_THEME& theme)
{
	if (context_ == nullptr || swap_chain_ == nullptr || target_ == nullptr)
	{
		return false;
	}

	const float clear_color[4] = {
		color_channel(theme.Background, 16),
		color_channel(theme.Background, 8),
		color_channel(theme.Background, 0),
		1.0f
	};

	context_->OMSetRenderTargets(1, target_.GetAddressOf(), nullptr);
	context_->ClearRenderTargetView(target_.Get(), clear_color);

	ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

	const HRESULT result = swap_chain_->Present(1, 0);

	return result != DXGI_ERROR_DEVICE_REMOVED && result != DXGI_ERROR_DEVICE_RESET && SUCCEEDED(result);
}

ID3D11Device* trace_renderer::device() const
{
	return device_.Get();
}

ID3D11DeviceContext* trace_renderer::context() const
{
	return context_.Get();
}

uint32_t trace_renderer::width() const
{
	return width_;
}

uint32_t trace_renderer::height() const
{
	return height_;
}

bool trace_renderer::create_target()
{
	if (swap_chain_ == nullptr || device_ == nullptr)
	{
		return false;
	}

	Microsoft::WRL::ComPtr<ID3D11Texture2D> back_buffer = {};
	HRESULT result = swap_chain_->GetBuffer(0, IID_PPV_ARGS(back_buffer.GetAddressOf()));

	if (FAILED(result) || back_buffer == nullptr)
	{
		return false;
	}

	result = device_->CreateRenderTargetView(back_buffer.Get(), nullptr, target_.ReleaseAndGetAddressOf());

	return SUCCEEDED(result) && target_ != nullptr;
}

void trace_renderer::release_target()
{
	target_.Reset();
}
