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

#ifndef MOCK_ITRANSCODER_ENGINE_H
#define MOCK_ITRANSCODER_ENGINE_H

#include "i_transcoder_engine.h"
#include "gmock/gmock.h"

namespace OHOS {
namespace Media {
class MockITransCoderEngineObs : public ITransCoderEngineObs {
public:
    MockITransCoderEngineObs() = default;
    ~MockITransCoderEngineObs() override = default;

    MOCK_METHOD(void, OnError, (TransCoderErrorType errorType, int32_t errorCode), (override));
    MOCK_METHOD(void, OnInfo, (TransCoderOnInfoType type, int32_t extra), (override));
};

class MockITransCoderEngine : public ITransCoderEngine {
public:
    MockITransCoderEngine() = default;
    ~MockITransCoderEngine() override {};

    MOCK_METHOD(void, SetInstanceId, (uint64_t instanceId), ());
    MOCK_METHOD(int32_t, SetInputFile, (const std::string &url), ());
    MOCK_METHOD(int32_t, SetOutputFile, (const int32_t fd), ());
    MOCK_METHOD(int32_t, SetOutputFormat, (OutputFormatType format), ());
    MOCK_METHOD(int32_t, SetObs, (const std::weak_ptr<ITransCoderEngineObs> &obs), ());
    MOCK_METHOD(int32_t, Configure, (const TransCoderParam &recParam), ());
    MOCK_METHOD(int32_t, Prepare, (), ());
    MOCK_METHOD(int32_t, Start, (), ());
    MOCK_METHOD(int32_t, Pause, (), ());
    MOCK_METHOD(int32_t, Resume, (), ());
    MOCK_METHOD(int32_t, Cancel, (), ());
    MOCK_METHOD(int32_t, GetCurrentTime, (int32_t &currentTime), ());
    MOCK_METHOD(int32_t, GetDuration, (int32_t &duration), ());
};
} // namespace Media
} // namespace OHOS
#endif