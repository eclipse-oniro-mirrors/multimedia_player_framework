/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_HDI_LOW_POWER_PLAYER_V1_0_ILPPSYNCMANAGERADAPTER_H
#define OHOS_HDI_LOW_POWER_PLAYER_V1_0_ILPPSYNCMANAGERADAPTER_H

#include <refbase.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "ilpp_sync_manager_callback.h"
#include "surface_buffer.h"
#include "../native_buffer.h"
#include "hdf_base.h"

namespace OHOS {
namespace HDI {
namespace LowPowerPlayer {
namespace V1_0 {
using namespace OHOS::HDI::Base;
class ILppSyncManagerAdapter : public RefBase {
public:
    MOCK_METHOD(int32_t, SetVideoChannelId, (uint32_t channelId));
    MOCK_METHOD(int32_t, SetAudioChannelId, (uint32_t channelId));
    MOCK_METHOD(int32_t, StartRender, ());
    MOCK_METHOD(int32_t, RenderNextFrame, ());
    MOCK_METHOD(int32_t, Pause, ());
    MOCK_METHOD(int32_t, Resume, ());
    MOCK_METHOD(int32_t, Flush, ());
    MOCK_METHOD(int32_t, Stop, ());
    MOCK_METHOD(int32_t, Reset, ());
    MOCK_METHOD(int32_t, SetTargetStartFrame, (uint64_t framePts, uint32_t timeoutMs));
    MOCK_METHOD(int32_t, SetPlaybackSpeed, (float speed));
    MOCK_METHOD(int32_t, RegisterCallback, (const sptr<ILppSyncManagerCallback>& syncCallback));
    MOCK_METHOD(int32_t, SetParameter, ((const std::map<std::string, std::string>)& parameter));
    MOCK_METHOD(int32_t, GetParameter, ((std::map<std::string, std::string>)& parameter));
    MOCK_METHOD(int32_t, UpdateTimeAnchor, (int64_t anchorPts, int64_t anchorClk));
    MOCK_METHOD(int32_t, BindOutputBuffers, ((const std::map<uint32_t, sptr<NativeBuffer>>)& outputBuffers));
    MOCK_METHOD(int32_t, UnbindOutputBuffers, ());
    MOCK_METHOD(int32_t, GetShareBuffer, (int& fd));
    MOCK_METHOD(int32_t, SetTunnelId, (uint64_t tunnelId));
    MOCK_METHOD(int32_t, GetLatestPts, (int64_t &pts));
};
} // V1_0
} // LowPowerPlayer
} // HDI
} // OHOS
#endif  // OHOS_HDI_LOW_POWER_PLAYER_V1_0_ILPPSYNCMANAGERADAPTER_H
