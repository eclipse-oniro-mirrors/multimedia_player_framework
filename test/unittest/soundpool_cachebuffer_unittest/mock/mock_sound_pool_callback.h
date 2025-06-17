
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
#ifndef MOCK_SOUND_POOL_CALLBACK_H
#define MOCK_SOUND_POOL_CALLBACK_H

#include "isoundpool.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace Media {
class MockSoundPoolCallback : public ISoundPoolCallback {
public:
    MockSoundPoolCallback() = default;
    virtual ~MockSoundPoolCallback() = default;

    MOCK_METHOD(void, OnLoadCompleted, (int32_t soundId), (override));
    MOCK_METHOD(void, OnPlayFinished, (int32_t streamID), (override));
    MOCK_METHOD(void, OnError, (int32_t errorCode), (override));
    MOCK_METHOD(void, OnErrorOccurred, (Format &errorInfo), (override));
};

} // namespace Media
} // namespace OHOS
#endif // MOCK_SOUND_POOL_CALLBACK_H
