/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "recorder_server_unit_test.h"
#include <string>
#include <unistd.h>
#include "media_errors.h"
#include "media_log.h"
#include "recorder_utils.h"

using namespace OHOS;
using namespace OHOS::Media;
using namespace std;
using namespace testing::ext;

namespace {
constexpr int32_t DUMP_PIPE_READ = 0;
constexpr int32_t DUMP_PIPE_WRITE = 1;
} // namespace

/**
 * @tc.name: Coverage4_DumpInfo_Snapshot_001
 * @tc.desc: DumpInfo outputs current state, config and last error message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage4_DumpInfo_Snapshot_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_CONFIGURED;
    RS()->config_.videoCodec = H264;
    RS()->config_.audioCodec = AudioCodecFormat::AAC_LC;
    RS()->config_.width = 1920;
    RS()->config_.height = 1080;
    RS()->config_.frameRate = 30;
    RS()->config_.bitRate = 2000000;
    RS()->config_.audioSampleRate = 48000;
    RS()->config_.audioChannel = 2;
    RS()->config_.audioBitRate = 96000;
    RS()->lastErrMsg_ = "dump_error_msg";

    int32_t fds[2] = { -1, -1 };
    ASSERT_EQ(0, pipe(fds));
    EXPECT_EQ(MSERR_OK, RS()->DumpInfo(fds[DUMP_PIPE_WRITE]));
    close(fds[DUMP_PIPE_WRITE]);

    char buf[4096] = { 0 };
    ssize_t len = read(fds[DUMP_PIPE_READ], buf, sizeof(buf) - 1);
    close(fds[DUMP_PIPE_READ]);
    ASSERT_GT(len, 0);

    std::string dump(buf);
    EXPECT_NE(std::string::npos, dump.find("current state is: " +
        std::to_string(RecorderServer::REC_CONFIGURED)));
    EXPECT_NE(std::string::npos, dump.find("last error is: dump_error_msg"));
    EXPECT_NE(std::string::npos, dump.find("width is: 1920"));
    EXPECT_NE(std::string::npos, dump.find("height is: 1080"));
    EXPECT_NE(std::string::npos, dump.find("audioChannel is: 2"));
    EXPECT_NE(std::string::npos, dump.find("audioSampleRate is: 48000"));
    EXPECT_EQ(MSERR_OK, RS()->DumpInfo(-1));
}

/**
 * @tc.name: Coverage4_DumpInfo_NoError_001
 * @tc.desc: DumpInfo omits the error line when the last error message is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage4_DumpInfo_NoError_001, TestSize.Level2)
{
    RS()->status_ = RecorderServer::REC_INITIALIZED;
    RS()->lastErrMsg_ = "";

    int32_t fds[2] = { -1, -1 };
    ASSERT_EQ(0, pipe(fds));
    EXPECT_EQ(MSERR_OK, RS()->DumpInfo(fds[DUMP_PIPE_WRITE]));
    close(fds[DUMP_PIPE_WRITE]);

    char buf[4096] = { 0 };
    ssize_t len = read(fds[DUMP_PIPE_READ], buf, sizeof(buf) - 1);
    close(fds[DUMP_PIPE_READ]);
    ASSERT_GT(len, 0);
    std::string dump(buf);
    EXPECT_EQ(std::string::npos, dump.find("last error is:"));
}

/**
 * @tc.name: Coverage4_SetMetaDataReport_Derived_001
 * @tc.desc: Non-HDR recording writes container MIME, resolution and HDR type into statistics
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage4_SetMetaDataReport_Derived_001, TestSize.Level2)
{
    RS()->config_.isHdr = false;
    RS()->config_.videoCodec = H264;
    RS()->config_.audioCodec = AudioCodecFormat::AAC_LC;
    RS()->config_.format = FORMAT_MPEG_4;
    RS()->config_.width = 1920;
    RS()->config_.height = 1080;
    RS()->config_.bitRate = 2000000;
    RS()->config_.audioSampleRate = 48000;
    RS()->config_.audioChannel = 2;
    RS()->config_.audioBitRate = 96000;
    RS()->statisticalEventInfo_.recordDuration = 30000;
    RS()->statisticalEventInfo_.startLatency = 100;
    RS()->statisticalEventInfo_.errCode = MSERR_OK;
    RS()->statisticalEventInfo_.errMsg = "no error";

    RS()->SetMetaDataReport();

    std::string expectMime = RS()->GetVideoMime(H264) + ";" + RS()->GetAudioMime(AudioCodecFormat::AAC_LC);
    EXPECT_EQ(expectMime, RS()->statisticalEventInfo_.containerMime);
    EXPECT_EQ(std::string("1920x1080"), RS()->statisticalEventInfo_.videoResolution);
    EXPECT_EQ(static_cast<int8_t>(RecorderServer::HdrType::HDR_TYPE_NONE),
        RS()->statisticalEventInfo_.hdrType);
}

/**
 * @tc.name: Coverage4_SetMetaDataReport_Hdr_001
 * @tc.desc: HDR recording reports HDR_TYPE_VIVID together with the configured resolution
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RecorderServerUnitTest, Coverage4_SetMetaDataReport_Hdr_001, TestSize.Level2)
{
    RS()->config_.isHdr = true;
    RS()->config_.videoCodec = H264;
    RS()->config_.audioCodec = AudioCodecFormat::AAC_LC;
    RS()->config_.format = FORMAT_MPEG_4;
    RS()->config_.width = 3840;
    RS()->config_.height = 2160;

    RS()->SetMetaDataReport();

    EXPECT_EQ(std::string("3840x2160"), RS()->statisticalEventInfo_.videoResolution);
    EXPECT_EQ(static_cast<int8_t>(RecorderServer::HdrType::HDR_TYPE_VIVID),
        RS()->statisticalEventInfo_.hdrType);
}
