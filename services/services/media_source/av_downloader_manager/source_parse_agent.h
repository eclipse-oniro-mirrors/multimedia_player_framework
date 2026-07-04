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

#ifndef SOURCE_PARSE_AGENT_H
#define SOURCE_PARSE_AGENT_H

#include <memory>
#include <mutex>
#include <string>
#include "http_source_plugin_stream_resource_parser.h"

namespace OHOS {
namespace Media {

constexpr size_t MIN_SNIFF_BUFFER_SIZE = 256;

class SourceParseAgent {
public:
    static bool Create();       // 加载so
    static void Destroy();      // 卸载so

    static size_t GetSniffBufferSize();

    static Plugins::HttpPlugin::StreamProtocolType SniffStreamProtocol(const uint8_t* data, size_t size);

    static std::unique_ptr<Plugins::HttpPlugin::StreamResourceParser> GetStreamResourceParser(
        const uint8_t* data, size_t size, Plugins::HttpPlugin::StreamProtocolType protocol,
        const std::string& rootUrl);

private:
    static void *handler_;      // so句柄
    static size_t (*getSniffBufferSizeFunc_)();
    static Plugins::HttpPlugin::StreamProtocolType (*sniffStreamProtocolFunc_)(const uint8_t* data, size_t size);

    static Plugins::HttpPlugin::StreamResourceParser* (*getStreamResourceParserFunc_)(
        const uint8_t* data, size_t size, Plugins::HttpPlugin::StreamProtocolType protocol,
        const std::string& rootUrl);

    static std::mutex loadMutex_;       // so保护的锁
    static void DestroyInner();
};

} // namespace Media
} // namespace OHOS

#endif // SOURCE_PARSE_AGENT_H
