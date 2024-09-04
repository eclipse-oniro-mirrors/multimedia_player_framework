/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#ifndef OH_VEF_EDITOR_IMPL_H
#define OH_VEF_EDITOR_IMPL_H

#include <mutex>
#include "video_editor.h"
#include "data_center/data_center.h"
#include "composite_engine/composite_engine.h"

namespace OHOS {
namespace Media {

enum class VideoEditorState : int32_t {
    INIT,
    IDLE,
    COMPOSITING,
    CANCELLING
};

class VideoEditorImpl : public VideoEditor {
public:
    explicit VideoEditorImpl(uint64_t id);
    ~VideoEditorImpl() override;

    uint64_t GetId() const;
    VideoEditorState GetState() const;

    VEFError Init();

    VEFError AppendVideoFile(int fileFd, const std::string &effectDescription) override;
    VEFError StartComposite(const std::shared_ptr<CompositionOptions> &options) override;
    VEFError CancelComposite() override;

private:
    void OnCompositeResult(VEFResult result);

private:
    mutable std::mutex editorLock_;
    uint64_t id_{ 0 };
    std::string logTag_;
    VideoEditorState state_{ VideoEditorState::INIT };
    std::shared_ptr<IDataCenter> dataCenter_{ nullptr };
    std::shared_ptr<ICompositeEngine> compositeEngine_{ nullptr };
};
}  // namespace Media
}  // namespace OHOS

#endif  // OH_VEF_EDITOR_IMPL_H
