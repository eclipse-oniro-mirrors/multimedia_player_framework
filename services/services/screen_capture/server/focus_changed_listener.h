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

#ifndef FOCUS_CHANGED_LISTENER_H
#define FOCUS_CHANGED_LISTENER_H

#include "window_manager.h"

namespace OHOS {
namespace Media {
class ScreenCaptureServer;

class FocusChangedListener : public Rosen::IFocusChangedListener {
public:
    explicit FocusChangedListener(std::weak_ptr<ScreenCaptureServer> screenCaptureServer);
    ~FocusChangedListener() override = default;
    void OnFocused(const sptr<Rosen::FocusChangeInfo>& focusChangeInfo) override;
    void OnUnfocused(const sptr<Rosen::FocusChangeInfo>& focusChangeInfo) override;
private:
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer_;
};
}
}
#endif // WINDOW_LIFE_CYCLE_LISTENER_H