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

#include "video_editor.h"

namespace OHOS {
namespace Media {
class VideoEditorImpl : public VideoEditor {
public:
    explicit VideoEditorImpl(uint64_t id);
    ~VideoEditorImpl() override;

    uint64_t GetId() const;
    VEFError Init();

    VEFError AppendVideoFile(int fileFd, const std::string &effectDescription) override;
    VEFError StartComposite(const std::shared_ptr<CompositionOptions> &options) override;
    VEFError CancelComposite() override;

private:
    uint64_t id_;
    std::string logTag_ = "";
};
}  // namespace Media
}  // namespace OHOS

#endif  // OH_VEF_EDITOR_IMPL_H