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

#include "source_parse_agent_test.h"
#include "source_parse_agent.cpp"

using namespace testing;
using namespace testing::Ext;

namespace OHOS {
namespace Media {

HWTEST_F(SourceParseAgentTest, GetSniffBufferSize_001, TestSize.Level0)
{
    auto size = SourceParseAgent::GetSniffBufferSize();
    EXPECT_EQ(size, MIN_SNIFF_BUFFER_SIZE);
}

HWTEST_F(SourceParseAgentTest, SniffStreamProtocol_HTTP_001, TestSize.Level0)
{
    std::vector<uint8_t> data = {'H', 'T', 'T', 'P', '/', '1', '.', '1'};
    auto protocol = SourceParseAgent::SniffStreamProtocol(data.data(), data.size());
    EXPECT_EQ(protocol, Plugins::HttpPlugin::StreamProtocolType::HTTP);
}

HWTEST_F(SourceParseAgentTest, SniffStreamProtocol_HTTPS_001, TestSize.Level0)
{
    std::vector<uint8_t> data = {'H', 'T', 'T', 'P', 'S', '/', '1', '.'};
    auto protocol = SourceParseAgent::SniffStreamProtocol(data.data(), data.size());
    EXPECT_EQ(protocol, Plugins::HttpPlugin::StreamProtocolType::HTTPS);
}

HWTEST_F(SourceParseAgentTest, SniffStreamProtocol_HLS_001, TestSize.Level0)
{
    std::vector<uint8_t> data = {'#', 'E', 'X', 'T', 'M', '3', 'U'};
    auto protocol = SourceParseAgent::SniffStreamProtocol(data.data(), data.size());
    EXPECT_EQ(protocol, Plugins::HttpPlugin::StreamProtocolType::HLS);
}

HWTEST_F(SourceParseAgentTest, SniffStreamProtocol_DASH_001, TestSize.Level0)
{
    std::vector<uint8_t> data = {'<', 'M', 'P', 'D'};
    auto protocol = SourceParseAgent::SniffStreamProtocol(data.data(), data.size());
    EXPECT_EQ(protocol, Plugins::HttpPlugin::StreamProtocolType::DASH);
}

HWTEST_F(SourceParseAgentTest, SniffStreamProtocol_SmallData_001, TestSize.Level0)
{
    std::vector<uint8_t> data = {'H', 'T'};
    auto protocol = SourceParseAgent::SniffStreamProtocol(data.data(), data.size());
    EXPECT_EQ(protocol, Plugins::HttpPlugin::StreamProtocolType::HTTP);
}

HWTEST_F(SourceParseAgentTest, SniffStreamProtocol_EmptyData_001, TestSize.Level0)
{
    std::vector<uint8_t> data;
    auto protocol = SourceParseAgent::SniffStreamProtocol(data.data(), data.size());
    EXPECT_EQ(protocol, Plugins::HttpPlugin::StreamProtocolType::UNKNOWN);
}

HWTEST_F(SourceParseAgentTest, SniffStreamProtocol_UnrecognizedData_001, TestSize.Level0)
{
    std::vector<uint8_t> data = {'R', 'A', 'N', 'D', 'O', 'M'};
    auto protocol = SourceParseAgent::SniffStreamProtocol(data.data(), data.size());
    EXPECT_EQ(protocol, Plugins::HttpPlugin::StreamProtocolType::UNKNOWN);
}

} // namespace Media
} // namespace OHOS
