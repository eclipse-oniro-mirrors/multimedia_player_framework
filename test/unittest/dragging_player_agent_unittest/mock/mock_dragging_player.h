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

#ifndef MOCK_DRAGGING_PLAYER_H
#define MOCK_DRAGGING_PLAYER_H

#include "gmock/gmock.h"
#include "dragging_player.h"

namespace OHOS {
namespace Media {
class MockDraggingPlayer : public DraggingPlayer {
public:
    virtual ~MockDraggingPlayer() = default;

    MOCK_METHOD2(Init, Status(const std::shared_ptr<OHOS::Media::Pipeline::DemuxerFilter> &,
        const std::shared_ptr<OHOS::Media::Pipeline::DecoderSurfaceFilter> &));
    MOCK_METHOD1(UpdateSeekPos, void(int64_t));
    MOCK_METHOD1(IsVideoStreamDiscardable, bool(const std::shared_ptr<AVBuffer>));
    MOCK_METHOD2(ConsumeVideoFrame, void(const std::shared_ptr<AVBuffer>, uint32_t));
    MOCK_METHOD0(StopDragging, void());
    MOCK_METHOD0(Release, void());
};
} // namespace Media
} // namespace OHOS
#endif // MOCK_DRAGGING_PLAYER_H