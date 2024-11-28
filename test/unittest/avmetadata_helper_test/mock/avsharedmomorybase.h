/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_MEDIA_AV_SHARED_MEMORY_BASE_H
#define OHOS_MEDIA_AV_SHARED_MEMORY_BASE_H

#include <string>
#include "buffer/avsharedmemory.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace Media {
class AVSharedMemoryBase {
public:
    MOCK_METHOD(std::shared_ptr<AVSharedMemory>, CreateFromLocal, (int32_t size, uint32_t flags, const std::string &name), ());

    MOCK_METHOD(std::shared_ptr<AVSharedMemory>, CreateFromRemote, (int32_t fd, int32_t size, uint32_t flags, const std::string &name), ());

    ~AVSharedMemoryBase() = default;
    AVSharedMemoryBase() = default;

    AVSharedMemoryBase(int32_t size, uint32_t flags, const std::string &name) {};

    MOCK_METHOD(int32_t, Init, (bool isMapVirAddr), ());

    MOCK_METHOD(int32_t, GetFd, (), ());

    MOCK_METHOD(std::string, GetName, (), ());

    MOCK_METHOD(int32_t, Write, (const uint8_t *in, int32_t writeSize, int32_t position), ());

    MOCK_METHOD(int32_t, Read, (uint8_t *out, int32_t readSize, int32_t position), ());

    MOCK_METHOD(int32_t, GetUsedSize, (), ());

    MOCK_METHOD(void, ClearUsedSize, (), ());

    MOCK_METHOD(uint8_t*, GetBase, (), ());

    MOCK_METHOD(int32_t, GetSize, (), ());

    MOCK_METHOD(uint32_t, GetFlags, (), ());
};
} // namespace Media
} // namespace OHOS

#endif