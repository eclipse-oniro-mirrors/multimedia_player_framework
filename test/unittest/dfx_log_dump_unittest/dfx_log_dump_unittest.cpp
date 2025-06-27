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

#include "dfx_log_dump_unittest.h"

namespace OHOS {
namespace Media {
using namespace std;
using namespace testing;
using namespace testing::ext;

static const int32_t NUM_0 = 0;
static const int32_t NUM_1 = 1;
static const int32_t NUM_10 = 10;
static const int32_t NUM_100 = 100;
static const int32_t NUM_123 = 123;
static const int32_t NUM_2048 = 2048;
static const int32_t NUM_50000 = 50000;

static OHOS::HiviewDFX::HiLogLabel MakeLabel()
{
    return {LOG_CORE, 0, "TestTag"};
}

void DfxLogDumpUnitTest::SetUpTestCase(void) {}

void DfxLogDumpUnitTest::TearDownTestCase(void) {}

void DfxLogDumpUnitTest::SetUp(void)
{
    dump_ = std::make_shared<DfxLogDump>();
}

void DfxLogDumpUnitTest::TearDown(void)
{
    dump_ = nullptr;
}

/**
 * @tc.name  : Test SaveLog
 * @tc.number: SaveLog_001
 * @tc.desc  : Test dtsPos != std::string::npos
 *             Test ret < 0
 *             Test ret >= 0
 *             Test lineCount_ >= FILE_LINE_MAX
 */
HWTEST_F(DfxLogDumpUnitTest, SaveLog_001, TestSize.Level0)
{
    ASSERT_NE(dump_, nullptr);

    // Test dtsPos != std::string::npos
    // Test ret >= 0
    dump_->isEnable_ = true;
    dump_->lineCount_ = NUM_0;
    dump_->logString_.clear();
    dump_->SaveLog("I", MakeLabel(), "test {public} log %d", NUM_123);
    EXPECT_FALSE(dump_->logString_.empty());
    EXPECT_EQ(dump_->lineCount_, NUM_1);

    // Test ret < 0
    char longFmt[NUM_2048] = {NUM_0};
    std::fill_n(longFmt, sizeof(longFmt) - 1, 'A');
    longFmt[sizeof(longFmt) - NUM_1] = '\0';
    dump_->SaveLog("E", MakeLabel(), longFmt);
    EXPECT_NE(dump_->logString_.find("dump log error"), std::string::npos);
    
    // Test lineCount_ >= FILE_LINE_MAX
    constexpr int32_t FILE_LINE_MAX = NUM_50000;
    dump_->lineCount_ = FILE_LINE_MAX - NUM_1;
    dump_->SaveLog("W", MakeLabel(), "last line");
    EXPECT_EQ(dump_->lineCount_, FILE_LINE_MAX);
}

/**
 * @tc.name  : Test UpdateCheckEnable
 * @tc.number: UpdateCheckEnable_001
 * @tc.desc  : Test ofStream.is_open() == true
 */
HWTEST_F(DfxLogDumpUnitTest, DoPause_001, TestSize.Level0)
{
    ASSERT_NE(dump_, nullptr);
    system("mkdir -p /data/test/log");
    dump_->isEnable_ = false;
    dump_->UpdateCheckEnable();
    EXPECT_TRUE(dump_->isEnable_);
}

/**
 * @tc.name  : Test TaskProcessor
 * @tc.number: TaskProcessor_001
 * @tc.desc  : Test isNewFile_ == false
 *             Test lineCount < FILE_LINE_MAX
 */
HWTEST_F(DfxLogDumpUnitTest, TaskProcessor_001, TestSize.Level0)
{
    ASSERT_NE(dump_, nullptr);

    // Test isNewFile_ == false
    dump_->isNewFile_ = false;
    dump_->fileCount_ = NUM_0;
    // Test lineCount < FILE_LINE_MAX
    dump_->lineCount_ = NUM_10;
    dump_->logString_ = "test log\n";
    dump_->isDump_ = true;
    dump_->isExit_ = false;

    system("mkdir -p /data/test/log");

    std::thread t([this] {
        std::this_thread::sleep_for(std::chrono::milliseconds(NUM_100));
        dump_->isExit_ = true;
        dump_->cond_.notify_all();
    });
    dump_->TaskProcessor();
    t.join();

    EXPECT_FALSE(dump_->isNewFile_);
    EXPECT_EQ(dump_->fileCount_, NUM_0);
}

} // namespace Media
} // namespace OHOS