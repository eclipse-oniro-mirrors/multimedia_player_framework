/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef I_MEDIA_DATA_SOURCE_MOCK_H
#define I_MEDIA_DATA_SOURCE_MOCK_H

#include "gmock/gmock.h"
#include "media_data_source.h"

namespace OHOS {
namespace Media {
class MockIMediaDataSource : public IMediaDataSource {
public:
    MockIMediaDataSource() = default;
    ~MockIMediaDataSource() override {};
    MOCK_METHOD(int32_t, ReadAt, (const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos), (override));
    MOCK_METHOD(int32_t, GetSize, (int64_t &size), (override));
    MOCK_METHOD(int32_t, ReadAt, (int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem), (override));
    MOCK_METHOD(int32_t, ReadAt, (uint32_t length, const std::shared_ptr<AVSharedMemory> &mem), (override));
};
} // namespace Media
} // namespace OHOS
#endif // I_MEDIA_DATA_SOURCE_MOCK_H