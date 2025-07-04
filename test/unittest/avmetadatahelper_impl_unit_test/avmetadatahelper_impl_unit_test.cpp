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

#include "avmetadatahelper_impl.h"
#include "gtest/gtest.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {
namespace {
class MockMediaDataSource : public IMediaDataSource {
public:
    virtual ~MockMediaDataSource() = default;
    int32_t ReadAt(const std::shared_ptr<AVSharedMemory> &mem, uint32_t length, int64_t pos = -1) override
    {
        (void)mem;
        (void)length;
        (void)pos;
        return MSERR_OK;
    }
    int32_t GetSize(int64_t &size) override
    {
        (void)size;
        return MSERR_OK;
    }
    int32_t ReadAt(int64_t pos, uint32_t length, const std::shared_ptr<AVSharedMemory> &mem) override
    {
        (void)pos;
        (void)length;
        (void)mem;
        return MSERR_OK;
    }
    int32_t ReadAt(uint32_t length, const std::shared_ptr<AVSharedMemory> &mem) override
    {
        (void)length;
        (void)mem;
        return MSERR_OK;
    }
};
}
class AVMetaDataHelperImplUnitTest : public testing::Test {
public:
    // SetUpTestCase: Called before all test cases
    static void SetUpTestCase(void) {}
    // TearDownTestCase: Called after all test case
    static void TearDownTestCase(void) {}
    // SetUp: Called before each test cases
    void SetUp(void);
    // TearDown: Called after each test cases
    void TearDown(void);
private:
    std::shared_ptr<AVMetadataHelperImpl> metadata_;
};

void AVMetaDataHelperImplUnitTest::SetUp()
{
    metadata_ = std::make_shared<AVMetadataHelperImpl>(0, 0, 0, "mock");
}

void AVMetaDataHelperImplUnitTest::TearDown()
{
    if (metadata_) {
        metadata_->Destroy();
    }
}

/**
 * @tc.name  : Test SetSource
 * @tc.number: SetSource_001
 * @tc.desc  : Test uriHelper.UriType() != UriHelper::URI_TYPE_FILE && uriHelper.UriType() != UriHelper::URI_TYPE_FD
 */
HWTEST_F(AVMetaDataHelperImplUnitTest, SetSource_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, metadata_);
    ASSERT_EQ(MSERR_UNSUPPORT, metadata_->SetSource("http://mock", 0));
}

/**
 * @tc.name  : Test SetSourceInternel
 * @tc.number: SetSourceInternel_001
 * @tc.desc  : Test interruptMonitor_ == nullptr
 */
HWTEST_F(AVMetaDataHelperImplUnitTest, SetSourceInternel_001, TestSize.Level1)
{
    ASSERT_NE(nullptr, metadata_);
    metadata_->mediaDemuxer_ = std::make_shared<MediaDemuxer>();
    ASSERT_NE(nullptr, metadata_->mediaDemuxer_);
    metadata_->metadataCollector_ = std::make_shared<AVMetaDataCollector>(metadata_->mediaDemuxer_);
    metadata_->thumbnailGenerator_ = std::make_shared<AVThumbnailGenerator>(metadata_->mediaDemuxer_, 0, 0, 0, 0);
    ASSERT_NE(nullptr, metadata_->metadataCollector_);
    ASSERT_NE(nullptr, metadata_->thumbnailGenerator_);
    metadata_->interruptMonitor_.reset();
    ASSERT_EQ(Status::ERROR_INVALID_PARAMETER, metadata_->SetSourceInternel("mock", false));
}

/**
 * @tc.name  : Test SetSourceInternel
 * @tc.number: SetSourceInternel_002
 * @tc.desc  : Test SetSourceInternel
 */
HWTEST_F(AVMetaDataHelperImplUnitTest, SetSourceInternel_002, TestSize.Level1)
{
    ASSERT_NE(nullptr, metadata_);
    std::shared_ptr<MockMediaDataSource> dataSource = std::make_shared<MockMediaDataSource>();
    ASSERT_EQ(Status::ERROR_INVALID_PARAMETER, metadata_->SetSourceInternel(dataSource));
    metadata_->interruptMonitor_.reset();
    ASSERT_EQ(Status::ERROR_INVALID_PARAMETER, metadata_->SetSourceInternel(dataSource));
}

/**
 * @tc.name  : Test SetSourceInternel
 * @tc.number: SetSourceInternel_003
 * @tc.desc  : Test SetSourceInternel
 */
HWTEST_F(AVMetaDataHelperImplUnitTest, SetSourceInternel_003, TestSize.Level1)
{
    ASSERT_NE(nullptr, metadata_);
    std::string mockUri;
    std::map<std::string, std::string> mockMap;
    ASSERT_EQ(Status::ERROR_INVALID_PARAMETER, metadata_->SetSourceInternel(mockUri, mockMap));
    metadata_->interruptMonitor_.reset();
    mockMap["m"] = "mock";
    metadata_->SetInterruptState(false);
    ASSERT_EQ(Status::ERROR_INVALID_PARAMETER, metadata_->SetSourceInternel(mockUri, mockMap));
}
} // namespace Media
} // namespace OHOS
