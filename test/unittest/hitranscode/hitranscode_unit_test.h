/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef HITRANSCODE_UNIT_TEST_H
#define HITRANSCODE_UNIT_TEST_H

#include "gtest/gtest.h"
#include "hitranscoder_impl.h"
#include "demuxer_filter.h"
#include "transcoder_param.h"

namespace OHOS {
namespace Media {
class HitranscodeUnitTest : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void);
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void);
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);

    std::unique_ptr<HiTransCoderImpl> transcoder_;
    std::shared_ptr<Pipeline::DemuxerFilter> demuxerFilter_;
    bool isExistVideoTrack_{false};
    std::shared_ptr<Meta> videoEncFormat_;
    std::shared_ptr<Meta> audioEncFormat_;
    int32_t inputVideoWidth_{0};
    int32_t inputVideoHeight_{0};
};
} // namespace Media
} // namespace OHOS
#endif // HIPLAYER_IMPL_UNIT_TEST_H