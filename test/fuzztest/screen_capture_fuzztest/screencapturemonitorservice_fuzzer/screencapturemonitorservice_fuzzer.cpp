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

#include <cmath>
#include <iostream>
#include <unistd.h>
#include "screencapturemonitorservice_fuzzer.h"
#include "i_standard_screen_capture_monitor_service.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {

namespace {
    const uint8_t* g_data_ = nullptr;
    size_t g_size_ = 0;
    size_t g_pos_;
}

template<class T>
T GetData()
{
    T object {};
    size_t objectSize = sizeof(object);
    if (g_data_ == nullptr || objectSize > g_size_ - g_pos_) {
        return object;
    }
    errno_t ret = memcpy_s(&object, objectSize, g_data_ + g_pos_, objectSize);
    if (ret != EOK) {
        return {};
    }
    g_pos_ += objectSize;
    return object;
}

ScreenCaptureMonitorListenerTest::ScreenCaptureMonitorListenerTest()
{
}
ScreenCaptureMonitorListenerTest::~ScreenCaptureMonitorListenerTest()
{
}

void ScreenCaptureMonitorListenerTest::OnScreenCaptureStarted(int32_t pid)
{
    (void)pid;
}
void ScreenCaptureMonitorListenerTest::OnScreenCaptureFinished(int32_t pid)
{
    (void)pid;
}

void ScreenCaptureMonitorListenerTest::OnScreenCaptureDied()
{
}

ScreenCaptureMonitorServiceFuzzer::ScreenCaptureMonitorServiceFuzzer()
{
}

ScreenCaptureMonitorServiceFuzzer::~ScreenCaptureMonitorServiceFuzzer()
{
}

bool ScreenCaptureMonitorServiceFuzzer::FuzzScreenCaptureMonitorCase(uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return true;
    }
    
    g_data_ = data;
    g_size_ = size;
    g_pos_ = 0;

    std::shared_ptr<ScreenCaptureMonitorServer> screenCaptureMonitorServer =
        ScreenCaptureMonitorServer::GetInstance();
    sptr<ScreenCaptureMonitorListenerTest> listener = new ScreenCaptureMonitorListenerTest();
    screenCaptureMonitorServer->SetScreenCaptureMonitorCallback(listener);
    screenCaptureMonitorServer->RegisterScreenCaptureMonitorListener(listener);
    screenCaptureMonitorServer->UnregisterScreenCaptureMonitorListener(listener);
    int32_t pid = GetData<int32_t>();
    screenCaptureMonitorServer->CallOnScreenCaptureStarted(pid);
    int32_t started = GetData<bool>();
    screenCaptureMonitorServer->SetSystemScreenRecorderStatus(started);
    screenCaptureMonitorServer->RemoveScreenCaptureMonitorCallback(listener);
    return true;
}
}

bool FuzzScreenCaptureMonitorCase(uint8_t *data, size_t size)
{
    if (data == nullptr) {
        return true;
    }

    if (size < sizeof(int32_t)) {
        return true;
    }
    ScreenCaptureMonitorServiceFuzzer testScreenCaptureMonitor;
    return testScreenCaptureMonitor.FuzzScreenCaptureMonitorCase(data, size);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::FuzzScreenCaptureMonitorCase(data, size);
    return 0;
}
