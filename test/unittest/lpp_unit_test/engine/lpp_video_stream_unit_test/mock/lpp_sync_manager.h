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
#ifndef LPP_SYNC_MANAGER_H
#define LPP_SYNC_MANAGER_H

#include <gmock/gmock.h>
#include "i_lpp_sync_manager.h"
#include "lpp_sync_manager_adapter.h"
#include "pipeline/pipeline.h"

namespace OHOS {
namespace Media {
class LppSyncManager : public ILppSyncManager {
public:
    explicit LppSyncManager(std::string videoStreamerId, bool isLpp)
    {
        (void)videoStreamerId;
        (void)isLpp;
    }
    ~LppSyncManager() {};
    MOCK_METHOD(int32_t, Init, (), (override));
    MOCK_METHOD(int32_t, GetTimeAnchor, (int64_t&, int64_t&), (override));
    MOCK_METHOD(int32_t, SetVideoChannelId, (const uint32_t channelId), (override));
    MOCK_METHOD(int32_t, SetAudioChannelId, (const uint32_t channelId), (override));
    MOCK_METHOD(int32_t, Prepare, (), (override));
    MOCK_METHOD(int32_t, StartRender, (), (override));
    MOCK_METHOD(int32_t, RenderNextFrame, (), (override));
    MOCK_METHOD(int32_t, Pause, (), (override));
    MOCK_METHOD(int32_t, Resume, (), (override));
    MOCK_METHOD(int32_t, Flush, (), (override));
    MOCK_METHOD(int32_t, Stop, (), (override));
    MOCK_METHOD(int32_t, Reset, (), (override));
    MOCK_METHOD(int32_t, SetTargetStartFrame, (const uint64_t targetPts, uint32_t timeoutMs), (override));
    MOCK_METHOD(int32_t, SetPlaybackSpeed, (float speed), (override));
    MOCK_METHOD(int32_t, SetParameter, ((const std::map<std::string, std::string>)& parameters), (override));
    MOCK_METHOD(int32_t, GetParameter, ((std::map<std::string, std::string>)& parameters), (override));
    MOCK_METHOD(int32_t, UpdateTimeAnchor, (const int64_t anchorPts, const int64_t anchorClk), (override));
    MOCK_METHOD(int32_t, BindOutputBuffers, ((const std::map<uint32_t, sptr<SurfaceBuffer>>)& bufferMap), (override));
    MOCK_METHOD(int32_t, UnbindOutputBuffers, (), (override));
    MOCK_METHOD(int32_t, GetShareBuffer, (int32_t& fd), (override));
    MOCK_METHOD(int32_t, SetTunnelId, (uint64_t tunnelId), (override));
    MOCK_METHOD(int32_t, SetAudioIsLpp, (bool isLpp), (override));
    MOCK_METHOD(void, SetEventReceiver, (std::shared_ptr<Pipeline::EventReceiver> eventReceiver), (override));
};
}  // namespace Media
}  // namespace OHOS
#endif