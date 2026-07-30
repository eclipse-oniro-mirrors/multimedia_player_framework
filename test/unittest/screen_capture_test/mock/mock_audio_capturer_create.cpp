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

#include "audio_capturer.h"
#include <gmock/gmock.h>
#include "mock_audio_capturer.h"

using testing::Return;
using testing::_;
using testing::DoAll;
using testing::SetArgReferee;

namespace OHOS {
namespace AudioStandard {

std::unique_ptr<AudioCapturer> AudioCapturer::Create(
    const AudioCapturerOptions &options, const AppInfo &appInfo)
{
    auto mock = std::make_unique<testing::NiceMock<OHOS::Media::MockAudioCapturer>>();
    ON_CALL(*mock, Start()).WillByDefault(Return(true));
    ON_CALL(*mock, Stop()).WillByDefault(Return(true));
    ON_CALL(*mock, Release()).WillByDefault(Return(true));
    ON_CALL(*mock, Read(_, _, _)).WillByDefault(Return(4096));
    ON_CALL(*mock, GetBufferSize(_)).WillByDefault(DoAll(SetArgReferee<0>(size_t(4096)), Return(0)));
    ON_CALL(*mock, SetCapturerCallback(_)).WillByDefault(Return(0));
    return mock;
}

} // namespace AudioStandard
} // namespace OHOS
