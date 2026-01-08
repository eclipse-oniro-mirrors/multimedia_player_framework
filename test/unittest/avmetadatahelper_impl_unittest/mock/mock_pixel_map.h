/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_PIXEL_MAP_H
#define MOCK_PIXEL_MAP_H

#include "pixel_map.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace Media {
class MockPixelMap : public PixelMap {
public:
    MockPixelMap() = default;
    virtual ~MockPixelMap() = default;

    MOCK_METHOD0(GetWidth, int32_t());
    MOCK_METHOD0(GetHeight, int32_t());
    MOCK_METHOD0(GetPixelFormat, PixelFormat());
    MOCK_METHOD0(GetAllocatorType, AllocatorType());
    MOCK_CONST_METHOD0(GetFd, void *());
    MOCK_METHOD0(GetPixels, const uint8_t *());
    MOCK_METHOD0(GetByteCount, int32_t());
};
}  // namespace Media
}  // namespace OHOS
#endif // MOCK_PIXEL_MAP_H
