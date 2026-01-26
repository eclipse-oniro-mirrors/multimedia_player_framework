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

#ifndef SCREEN_CAPTURE_RECORD_DISPLAY_LISTENER_H
#define SCREEN_CAPTURE_RECORD_DISPLAY_LISTENER_H

#include <screen_manager.h>

namespace OHOS::Media {
class ScreenCaptureServer;

class SCRecordDisplayListener : public Rosen::ScreenManager::IRecordDisplayListener {
public:
    void OnChange(const std::vector<Rosen::DisplayId> &displayIds) override;
    explicit SCRecordDisplayListener(std::weak_ptr<ScreenCaptureServer> screenCaptureServer)
        : screenCaptureServer_(screenCaptureServer) {}

private:
    std::weak_ptr<ScreenCaptureServer> screenCaptureServer_;
};
}
#endif