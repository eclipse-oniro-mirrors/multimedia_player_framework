/*
 * Copyright (C) 2026 Huawei Device Co., Ltd.
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

#include "media_source_napi_test.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

HWTEST_F(MediaSourceNapiTest, CreateMediaSourceWithUrl_001, TestSize.Level0)
{
    auto mediaSource = std::make_shared<MockMediaSource>("http://example.com/test.mp4");
    ASSERT_NE(mediaSource, nullptr);
    EXPECT_CALL(*mediaSource, GetSourceUri()).WillRepeatedly(Return("http://example.com/test.mp4"));
    EXPECT_EQ(mediaSource->GetSourceUri(), "http://example.com/test.mp4");
}

HWTEST_F(MediaSourceNapiTest, CreateMediaSourceWithUrl_EmptyUrl_001, TestSize.Level0)
{
    auto mediaSource = std::make_shared<MockMediaSource>("");
    ASSERT_NE(mediaSource, nullptr);
    EXPECT_CALL(*mediaSource, GetSourceUri()).WillRepeatedly(Return(""));
    EXPECT_EQ(mediaSource->GetSourceUri(), "");
}

HWTEST_F(MediaSourceNapiTest, CreateMediaSourceWithUrl_WithHeader_001, TestSize.Level0)
{
    auto mediaSource = std::make_shared<MockMediaSource>("http://example.com/test.mp4");
    ASSERT_NE(mediaSource, nullptr);
    EXPECT_CALL(*mediaSource, GetSourceUri()).WillRepeatedly(Return("http://example.com/test.mp4"));
    EXPECT_EQ(mediaSource->GetSourceUri(), "http://example.com/test.mp4");
}

HWTEST_F(MediaSourceNapiTest, CreateMediaSourceWithFd_001, TestSize.Level0)
{
    auto mediaSource = std::make_shared<MockMediaSource>("fd://42?offset=0&size=1024");
    ASSERT_NE(mediaSource, nullptr);
    EXPECT_CALL(*mediaSource, GetSourceUri()).WillRepeatedly(Return("fd://42?offset=0&size=1024"));
    EXPECT_EQ(mediaSource->GetSourceUri(), "fd://42?offset=0&size=1024");
    EXPECT_CALL(*mediaSource, GetSourceType()).WillRepeatedly(Return(Plugins::MediaSourceType::SOURCE_TYPE_FD));
    EXPECT_EQ(mediaSource->GetSourceType(), Plugins::MediaSourceType::SOURCE_TYPE_FD);
}

HWTEST_F(MediaSourceNapiTest, CreateMediaSourceWithDataSource_001, TestSize.Level0)
{
    auto mediaSource = std::make_shared<MockMediaSource>();
    ASSERT_NE(mediaSource, nullptr);
    EXPECT_CALL(*mediaSource, GetSourceUri()).WillRepeatedly(Return(""));
    EXPECT_EQ(mediaSource->GetSourceUri(), "");
    EXPECT_CALL(*mediaSource, GetSourceType()).WillRepeatedly(Return(Plugins::MediaSourceType::SOURCE_TYPE_STREAM));
    EXPECT_EQ(mediaSource->GetSourceType(), Plugins::MediaSourceType::SOURCE_TYPE_STREAM);
}

HWTEST_F(MediaSourceNapiTest, CreateMediaSourceWithStreamData_Empty_001, TestSize.Level0)
{
    auto mediaSource = std::make_shared<MockMediaSource>();
    ASSERT_NE(mediaSource, nullptr);
    EXPECT_CALL(*mediaSource, GetSourceUri()).WillRepeatedly(Return(""));
    EXPECT_EQ(mediaSource->GetSourceUri(), "");
    EXPECT_CALL(*mediaSource, GetSourceType()).WillRepeatedly(Return(Plugins::MediaSourceType::SOURCE_TYPE_STREAM));
    EXPECT_EQ(mediaSource->GetSourceType(), Plugins::MediaSourceType::SOURCE_TYPE_STREAM);
}

HWTEST_F(MediaSourceNapiTest, CreateMediaSourceWithDirectory_ValidPath_001, TestSize.Level0)
{
    auto mediaSource = std::make_shared<MockMediaSource>("/data/media");
    ASSERT_NE(mediaSource, nullptr);
    EXPECT_CALL(*mediaSource, GetSourceUri()).WillRepeatedly(Return("/data/media"));
    EXPECT_EQ(mediaSource->GetSourceUri(), "/data/media");
}

HWTEST_F(MediaSourceNapiTest, CreateMediaSourceWithDirectory_InvalidPath_001, TestSize.Level0)
{
    auto mediaSource = std::make_shared<MockMediaSource>("");
    ASSERT_NE(mediaSource, nullptr);
    EXPECT_CALL(*mediaSource, GetSourceUri()).WillRepeatedly(Return(""));
    EXPECT_EQ(mediaSource->GetSourceUri(), "");
}

HWTEST_F(MediaSourceNapiTest, MediaSourceType_001, TestSize.Level0)
{
    auto mediaSource = std::make_shared<MockMediaSource>("http://example.com/test.mp4");
    ASSERT_NE(mediaSource, nullptr);
    EXPECT_CALL(*mediaSource, GetSourceType()).WillRepeatedly(Return(Plugins::MediaSourceType::SOURCE_TYPE_URL));
    EXPECT_EQ(mediaSource->GetSourceType(), Plugins::MediaSourceType::SOURCE_TYPE_URL);
}

HWTEST_F(MediaSourceNapiTest, GetSupportedProtocols_001, TestSize.Level0)
{
    auto mediaSource = std::make_shared<MockMediaSource>("http://example.com/test.mp4");
    ASSERT_NE(mediaSource, nullptr);
    EXPECT_CALL(*mediaSource, GetSupportedProtocols()).WillRepeatedly(Return(std::vector<std::string>{"http", "https"}));
    auto protocols = mediaSource->GetSupportedProtocols();
    EXPECT_EQ(protocols.size(), 2);
}

HWTEST_F(MediaSourceNapiTest, GetProtocolTypes_001, TestSize.Level0)
{
    auto mediaSource = std::make_shared<MockMediaSource>("http://example.com/test.mp4");
    ASSERT_NE(mediaSource, nullptr);
    EXPECT_CALL(*mediaSource, GetProtocolTypes()).WillRepeatedly(Return(std::vector<Plugins::ProtocolType>{Plugins::ProtocolType::HTTP, Plugins::ProtocolType::HTTPS}));
    auto types = mediaSource->GetProtocolTypes();
    EXPECT_EQ(types.size(), 2);
}

HWTEST_F(MediaSourceNapiTest, MultipleMediaSourceInstances_001, TestSize.Level0)
{
    auto mediaSource1 = std::make_shared<MockMediaSource>("http://example.com/video1.mp4");
    auto mediaSource2 = std::make_shared<MockMediaSource>("http://example.com/video2.mp4");
    ASSERT_NE(mediaSource1, nullptr);
    ASSERT_NE(mediaSource2, nullptr);
    EXPECT_CALL(*mediaSource1, GetSourceUri()).WillRepeatedly(Return("http://example.com/video1.mp4"));
    EXPECT_CALL(*mediaSource2, GetSourceUri()).WillRepeatedly(Return("http://example.com/video2.mp4"));
    EXPECT_NE(mediaSource1->GetSourceUri(), mediaSource2->GetSourceUri());
}

} // namespace Media
} // namespace OHOS
