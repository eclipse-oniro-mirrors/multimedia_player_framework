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

#include "media_source_loading_request_napi_test.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Media {

HWTEST_F(MediaSourceLoadingRequestNapiTest, GetUrl_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>();
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(*request, GetUrl()).WillOnce(Return("http://example.com/test.mp4"));
    EXPECT_EQ(request->GetUrl(), "http://example.com/test.mp4");
}

HWTEST_F(MediaSourceLoadingRequestNapiTest, GetUrl_Empty_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>();
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(*request, GetUrl()).WillOnce(Return(""));
    EXPECT_EQ(request->GetUrl(), "");
}

HWTEST_F(MediaSourceLoadingRequestNapiTest, GetHeader_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>();
    ASSERT_NE(request, nullptr);
    std::map<std::string, std::string> expectedHeader = {{"Content-Type", "video/mp4"}, {"Range", "bytes=0-1024"}};
    EXPECT_CALL(*request, GetHeader()).WillOnce(Return(expectedHeader));
    auto header = request->GetHeader();
    EXPECT_EQ(header.size(), 2);
    EXPECT_EQ(header["Content-Type"], "video/mp4");
}

HWTEST_F(MediaSourceLoadingRequestNapiTest, GetHeader_Empty_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>();
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(*request, GetHeader()).WillOnce(Return(std::map<std::string, std::string>{}));
    auto header = request->GetHeader();
    EXPECT_TRUE(header.empty());
}

HWTEST_F(MediaSourceLoadingRequestNapiTest, RespondData_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>();
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(*request, RespondData(_, _, _)).WillOnce(Return(0));
    auto mem = nullptr;
    auto result = request->RespondData(12345, 0, mem);
    EXPECT_EQ(result, 0);
}

HWTEST_F(MediaSourceLoadingRequestNapiTest, RespondData_WithOffset_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>();
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(*request, RespondData(12345, 1024, _)).WillOnce(Return(1024));
    auto mem = nullptr;
    auto result = request->RespondData(12345, 1024, mem);
    EXPECT_EQ(result, 1024);
}

HWTEST_F(MediaSourceLoadingRequestNapiTest, RespondHeader_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>();
    ASSERT_NE(request, nullptr);
    std::map<std::string, std::string> header = {{"Content-Type", "video/mp4"}};
    EXPECT_CALL(*request, RespondHeader(12345, _, "")).WillOnce(Return(0));
    auto result = request->RespondHeader(12345, header, "");
    EXPECT_EQ(result, 0);
}

HWTEST_F(MediaSourceLoadingRequestNapiTest, RespondHeader_WithRedirectUrl_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>();
    ASSERT_NE(request, nullptr);
    std::map<std::string, std::string> header = {{"Content-Type", "video/mp4"}};
    EXPECT_CALL(*request, RespondHeader(12345, _, "http://redirect.com/video.mp4")).WillOnce(Return(0));
    auto result = request->RespondHeader(12345, header, "http://redirect.com/video.mp4");
    EXPECT_EQ(result, 0);
}

HWTEST_F(MediaSourceLoadingRequestNapiTest, FinishLoading_Success_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>();
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(*request, FinishLoading(12345, 0)).WillOnce(Return(0));
    auto result = request->FinishLoading(12345, 0);
    EXPECT_EQ(result, 0);
}

HWTEST_F(MediaSourceLoadingRequestNapiTest, FinishLoading_WithError_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>();
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(*request, FinishLoading(12345, -1)).WillOnce(Return(-1));
    auto result = request->FinishLoading(12345, -1);
    EXPECT_EQ(result, -1);
}

HWTEST_F(MediaSourceLoadingRequestNapiTest, GetUniqueId_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>();
    ASSERT_NE(request, nullptr);
    EXPECT_CALL(*request, GetUniqueId()).WillOnce(Return(12345));
    EXPECT_EQ(request->GetUniqueId(), 12345);
}

HWTEST_F(MediaSourceLoadingRequestNapiTest, FullWorkflow_001, TestSize.Level0)
{
    auto request = std::make_shared<MockLoadingRequest>();
    ASSERT_NE(request, nullptr);

    EXPECT_CALL(*request, GetUrl()).WillOnce(Return("http://example.com/test.mp4"));
    EXPECT_CALL(*request, GetHeader()).WillOnce(Return(std::map<std::string, std::string>{{"Range", "bytes=0-1024"}}));
    EXPECT_CALL(*request, GetUniqueId()).WillOnce(Return(12345));
    EXPECT_CALL(*request, RespondData(12345, 0, _)).WillOnce(Return(1024));
    EXPECT_CALL(*request, FinishLoading(12345, 0)).WillOnce(Return(0));

    EXPECT_EQ(request->GetUrl(), "http://example.com/test.mp4");
    EXPECT_FALSE(request->GetHeader().empty());
    EXPECT_EQ(request->GetUniqueId(), 12345);
    EXPECT_EQ(request->RespondData(12345, 0, nullptr), 1024);
    EXPECT_EQ(request->FinishLoading(12345, 0), 0);
}

} // namespace Media
} // namespace OHOS
