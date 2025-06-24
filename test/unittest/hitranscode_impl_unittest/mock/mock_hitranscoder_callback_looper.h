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

#ifndef MOCK_HITRANSCODER_CALLBACKER_LOOPER_H
#define MOCK_HITRANSCODER_CALLBACKER_LOOPER_H

#include "hitranscoder_callback_looper.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace Media {
class MockHiTransCoderCallbackLooper : public HiTransCoderCallbackLooper {
public:
    explicit MockHiTransCoderCallbackLooper() = default;
    ~MockHiTransCoderCallbackLooper() override = default;

    MOCK_METHOD2(OnError, void(TransCoderErrorType errorType, int32_t errorCode));
    MOCK_METHOD2(OnInfo, void(TransCoderOnInfoType type, int32_t extra));
};
}  // namespace Media
}  // namespace OHOS
#endif // MOCK_HITRANSCODER_CALLBACKER_LOOPER_H
