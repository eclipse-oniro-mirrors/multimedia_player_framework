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
#ifndef AVMETADATA_COLLECTOR_UNIT_TEST_H
#define AVMETADATA_COLLECTOR_UNIT_TEST_H
 
#include "mock/mock_media_demuxer.h"
#include <condition_variable>
#include <mutex>
#include <nocopyable.h>
#include <set>
#include <unordered_map>
#include <avmetadata_collector.h>
 
#include "gtest/gtest.h"
#include "gmock/gmock.h"
#include "meta/meta.h"
#include "meta/meta_key.h"
 
namespace OHOS {
namespace Media {
namespace Test {
class AVMetaDataCollectorUnitTest : public testing::Test {
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
    std::shared_ptr<AVMetaDataCollector> avmetaDataCollector{ nullptr };
    std::shared_ptr<MediaDemuxer> mediaDemuxer_{ nullptr };
    std::shared_ptr<MockMediaDemuxer> mediaDemuxer{ nullptr };
};
}  // namespace Test
}  // namespace Media
}  // namespace OHOS
#endif  // AVMETADATA_COLLECTOR_UNIT_TEST_H