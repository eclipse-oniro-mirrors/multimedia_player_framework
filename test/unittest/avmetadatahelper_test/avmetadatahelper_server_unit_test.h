/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef AVMETADATAHELPER_SERVER_UNIT_TEST_H
#define AVMETADATAHELPER_SERVER_UNIT_TEST_H

#include <mutex>
#include "gtest/gtest.h"
#include "avmetadatahelper_server.h"
#include "i_avmetadatahelper_service.h"
#include "i_avmetadatahelper_engine.h"
#include "nocopyable.h"
#include "uri_helper.h"
#include "task_queue.h"

namespace OHOS {
namespace Media {
namespace Test {
class AVMetadataHelperServerUnitTest : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);

protected:
    std::shared_ptr<AVMetadataHelperServer> avmetadataHelperServer_{ nullptr };
};

class TestHelperCallback : public HelperCallback {
public:
    ~TestHelperCallback() = default;
    void OnInfo(HelperOnInfoType type, int32_t extra, const Format &infoBody = {})
    {
        return;
    }
    void OnError(int32_t errorCode, const std::string &errorMsg)
    {
        return;
    }
    void OnPixelComplete(HelperOnInfoType type,
                        const std::shared_ptr<AVBuffer> &reAvbuffer_,
                        const FrameInfo &info,
                        const PixelMapParams &param)
    {
        return;
    }
};
}  // namespace Test
}  // namespace Media
}  // namespace OHOS
#endif  // AVMETADATAHELPER_SERVER_UNIT_TEST_H