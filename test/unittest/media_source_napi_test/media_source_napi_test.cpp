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
    mediaSource_ = std::make_shared<AVMediaSource>("http://example.com/test.mp4", std::map<std::string, std::string>{});
    ASSERT_NE(mediaSource_, nullptr);
    EXPECT_EQ(mediaSource_->url, "http://example.com/test.mp4");
}

HWTEST_F(MediaSourceNapiTest, CreateMediaSourceWithUrl_EmptyUrl_001, TestSize.Level0)
{
    mediaSource_ = std::make_shared<AVMediaSource>("", std::map<std::string, std::string>{});
    ASSERT_NE(mediaSource_, nullptr);
    EXPECT_EQ(mediaSource_->url, "");
}

HWTEST_F(MediaSourceNapiTest, CreateMediaSourceWithHeader_001, TestSize.Level0)
{
    std::map<std::string, std::string> headers = {{"User-Agent", "test"}, {"Range", "bytes=0-1024"}};
    mediaSource_ = std::make_shared<AVMediaSource>("http://example.com/test.mp4", headers);
    ASSERT_NE(mediaSource_, nullptr);
    EXPECT_EQ(mediaSource_->url, "http://example.com/test.mp4");
    EXPECT_EQ(mediaSource_->header.size(), 2);
    EXPECT_EQ(mediaSource_->header["User-Agent"], "test");
}

HWTEST_F(MediaSourceNapiTest, CreateMediaSourceWithDirectory_001, TestSize.Level0)
{
    mediaSource_ = std::make_shared<AVMediaSource>("/data/media");
    ASSERT_NE(mediaSource_, nullptr);
    EXPECT_EQ(mediaSource_->GetDirectoryPath(), "/data/media");
}

HWTEST_F(MediaSourceNapiTest, MimeType_001, TestSize.Level0)
{
    mediaSource_ = std::make_shared<AVMediaSource>("http://example.com/test.mp4", std::map<std::string, std::string>{});
    ASSERT_NE(mediaSource_, nullptr);
    mediaSource_->SetMimeType("video/mp4");
    EXPECT_EQ(mediaSource_->GetMimeType(), "video/mp4");
}

HWTEST_F(MediaSourceNapiTest, OfflineCache_001, TestSize.Level0)
{
    mediaSource_ = std::make_shared<AVMediaSource>("http://example.com/test.mp4", std::map<std::string, std::string>{});
    ASSERT_NE(mediaSource_, nullptr);
    EXPECT_FALSE(mediaSource_->GetenableOfflineCache());
    mediaSource_->enableOfflineCache(true);
    EXPECT_TRUE(mediaSource_->GetenableOfflineCache());
}

HWTEST_F(MediaSourceNapiTest, Id_001, TestSize.Level0)
{
    mediaSource_ = std::make_shared<AVMediaSource>("http://example.com/test.mp4", std::map<std::string, std::string>{});
    ASSERT_NE(mediaSource_, nullptr);
    mediaSource_->SetID("test-id-123");
    EXPECT_EQ(mediaSource_->GetID(), "test-id-123");
}

HWTEST_F(MediaSourceNapiTest, MultipleMediaSourceInstances_001, TestSize.Level0)
{
    auto source1 = std::make_shared<AVMediaSource>("http://example.com/video1.mp4", std::map<std::string, std::string>{});
    auto source2 = std::make_shared<AVMediaSource>("http://example.com/video2.mp4", std::map<std::string, std::string>{});
    ASSERT_NE(source1, nullptr);
    ASSERT_NE(source2, nullptr);
    EXPECT_NE(source1->url, source2->url);
}

} // namespace Media
} // namespace OHOS
