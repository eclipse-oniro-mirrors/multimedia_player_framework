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
#ifndef AVMETADATAHELPER_IMPL_UNIT_TEST_H
#define AVMETADATAHELPER_IMPL_UNIT_TEST_H

#undef SUPPORT_RECORDER
#undef SUPPORT_TRANSCODER
#undef SUPPORT_PLAYER
#undef SUPPORT_SCREEN_CAPTURE

#include <unordered_map>
#include <set>
#include <condition_variable>
#include <mutex>
#include <nocopyable.h>
#include "gtest/gtest.h"
#include "avmetadatahelper_impl.cpp"
#include "buffer/avsharedmemorybase.h"
#include "common/status.h"
#include "i_avmetadatahelper_service.h"
#include "media_demuxer.h"
#include "pipeline/pipeline.h"
#include "video_decoder_adapter.h"

namespace OHOS {
namespace Media {
namespace Test {
class AVMetadtahelperImplUnitTest : public testing::Test {
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
    std::shared_ptr<AVMetadataHelperImpl> helper_{ nullptr };
};
}  // namespace Test
}  // namespace Media
}  // namespace OHOS
#endif  // AVMETADATAHELPER_IMPL_UNIT_TEST_H