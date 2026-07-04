/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <dlfcn.h>

#include "media_log.h"
#include "http_source_plugin_stream_resource_parser.h"
#include "source_parse_agent.h"

#ifndef MEDIA_LOGD
#define MEDIA_LOGD MEDIA_LOG_D
#endif
#ifndef MEDIA_LOGI
#define MEDIA_LOGI MEDIA_LOG_I
#endif
#ifndef MEDIA_LOGW
#define MEDIA_LOGW MEDIA_LOG_W
#endif
#ifndef MEDIA_LOGE
#define MEDIA_LOGE MEDIA_LOG_E
#endif

namespace OHOS {
namespace Media {

namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, LOG_DOMAIN_PLAYER, "SourceParseAgent"};
#if (defined(__aarch64__) || defined(__x86_64__))
static const std::string HTTP_SOURCE_SO_PATH = "/system/lib64/media/media_plugins/libmedia_plugin_HttpSource.z.so";
#else
static const std::string HTTP_SOURCE_SO_PATH = "/system/lib/media/media_plugins/libmedia_plugin_HttpSource.z.so";
#endif
}

void *SourceParseAgent::handler_ = nullptr;

size_t (*SourceParseAgent::getSniffBufferSizeFunc_)() = nullptr;

Plugins::HttpPlugin::StreamProtocolType (*SourceParseAgent::sniffStreamProtocolFunc_)(const uint8_t* data,
    size_t size) = nullptr;

Plugins::HttpPlugin::StreamResourceParser* (*SourceParseAgent::getStreamResourceParserFunc_)(
    const uint8_t* data, size_t size, Plugins::HttpPlugin::StreamProtocolType protocol,
    const std::string& rootUrl) = nullptr;

std::mutex SourceParseAgent::loadMutex_;

bool SourceParseAgent::Create()
{
    std::lock_guard<std::mutex> lock(loadMutex_);
    if (handler_ != nullptr && getSniffBufferSizeFunc_ != nullptr
        && sniffStreamProtocolFunc_ != nullptr && getStreamResourceParserFunc_ != nullptr) {
        return true;
    }
    DestroyInner();
    handler_ = ::dlopen(HTTP_SOURCE_SO_PATH.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (handler_ == nullptr) {
        MEDIA_LOGE("dlopen failed due to %{public}s", ::dlerror());
        return false;
    }
    // 获取SniffBufferSize方法
    using SniffSizeFuncType = size_t (*)();
    SniffSizeFuncType getSniffBufferSizeFunc = (SniffSizeFuncType)(::dlsym(handler_, "GetMinSniffBufferSize"));
    if (getSniffBufferSizeFunc == nullptr) {
        MEDIA_LOGE("sniffSizeFunc func is nullptr");
        DestroyInner();
        return false;
    }
    getSniffBufferSizeFunc_ = getSniffBufferSizeFunc;

    MEDIA_LOGE("getSniffBufferSizeFunc_ func success: %{public}d", (getSniffBufferSizeFunc_ == nullptr));

    // 获取协议类型
    using SniffProtocolFuncType = Plugins::HttpPlugin::StreamProtocolType (*)(const uint8_t* data, size_t size);
    SniffProtocolFuncType sniffStreamProtocolFunc =
        (SniffProtocolFuncType)(::dlsym(handler_, "SniffStreamProtocolFromData"));
    if (sniffStreamProtocolFunc == nullptr) {
        MEDIA_LOGE("sniffStreamProtocolFunc func is nullptr");
        DestroyInner();
        return false;
    }
    sniffStreamProtocolFunc_ = sniffStreamProtocolFunc;
    MEDIA_LOGE("sniffStreamProtocolFunc_ func success: %{public}d", (sniffStreamProtocolFunc_ == nullptr));

    // 获取流解析对象
    using StreamParserFuncType = Plugins::HttpPlugin::StreamResourceParser* (*)(
        const uint8_t* data, size_t size, Plugins::HttpPlugin::StreamProtocolType protocol,
        const std::string& rootUrl);

    StreamParserFuncType getStreamResourceParserFunc =
        (StreamParserFuncType)(::dlsym(handler_, "GetStreamResourceParser"));
    if (getStreamResourceParserFunc == nullptr) {
        MEDIA_LOGE("getStreamResourceParserFunc func is nullptr");
        DestroyInner();
        return false;
    }
    getStreamResourceParserFunc_ = getStreamResourceParserFunc;
    MEDIA_LOGE("getStreamResourceParserFunc_ func success: %{public}d", (getStreamResourceParserFunc_ == nullptr));

    MEDIA_LOGI("SourceParseAgent::Create success");
    return true;
}

void SourceParseAgent::Destroy()
{
    MEDIA_LOGI("SourceParseAgent::Destroy");
    std::lock_guard<std::mutex> lock(loadMutex_);
    DestroyInner();
}

void SourceParseAgent::DestroyInner()
{
    getSniffBufferSizeFunc_ = nullptr;
    MEDIA_LOGE("sniffStreamProtocolFunc func set nullptr");
    sniffStreamProtocolFunc_ = nullptr;
    getStreamResourceParserFunc_ = nullptr;
    if (handler_ != nullptr) {
        (void)dlclose(handler_);
        handler_ = nullptr;
    }
}

size_t SourceParseAgent::GetSniffBufferSize() // 获取buffer size
{
    if (getSniffBufferSizeFunc_ == nullptr) {
        MEDIA_LOGE("getSniffBufferSizeFunc_ is nullptr");
        return MIN_SNIFF_BUFFER_SIZE;
    }
    return getSniffBufferSizeFunc_();
}

Plugins::HttpPlugin::StreamProtocolType SourceParseAgent::SniffStreamProtocol(const uint8_t* data, size_t size)
{
    if (sniffStreamProtocolFunc_ == nullptr) {
        MEDIA_LOGE("sniffStreamProtocolFunc_ is nullptr");
        return Plugins::HttpPlugin::StreamProtocolType::HTTP;
    }
    return sniffStreamProtocolFunc_(data, size);
}

std::unique_ptr<Plugins::HttpPlugin::StreamResourceParser> SourceParseAgent::GetStreamResourceParser(
    const uint8_t* data, size_t size, Plugins::HttpPlugin::StreamProtocolType protocol,
    const std::string& rootUrl)
{
    if (getStreamResourceParserFunc_ == nullptr) {
        MEDIA_LOGE("getStreamResourceParserFunc_ is nullptr");
        return nullptr;
    }

    auto *parser = getStreamResourceParserFunc_(data, size, protocol, rootUrl);
    if (parser == nullptr) {
        MEDIA_LOGE("parser is nullptr");
        return nullptr;
    }
    

    return std::unique_ptr<Plugins::HttpPlugin::StreamResourceParser>(parser);
}

} // namespace Media
} // namespace OHOS
