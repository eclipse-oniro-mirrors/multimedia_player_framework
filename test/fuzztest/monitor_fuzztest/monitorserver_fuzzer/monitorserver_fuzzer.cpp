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
#include <fuzzer/FuzzedDataProvider.h>
#include "monitor_server.h"
#include "string_ex.h"
#include "directory_ex.h"
#include "monitorserver_fuzzer.h"

using namespace std;
using namespace OHOS;
using namespace Media;

namespace OHOS {
namespace Media {
const size_t ELEMENTS_MAX = 1000;
static const int32_t MIN_SIZE_NUM = 4;
static const size_t MAX_ALLOWED_SIZE = 4096;
MonitorServerFuzzer::MonitorServerFuzzer()
{
}

MonitorServerFuzzer::~MonitorServerFuzzer()
{
}

void MonitorServerFuzzer::ClickFuzzTest(FuzzedDataProvider& provider)
{
    auto monitorserver = std::make_unique<MonitorServer>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    monitorserver->Click(pid);
    monitorserver->EnableMonitor(pid);
    monitorserver->DisableMonitor(pid);
    monitorserver->OnClientDie(pid);
}

void MonitorServerFuzzer::GetTimeMSFuzzTest(FuzzedDataProvider& provider)
{
    auto monitorserver = std::make_unique<MonitorServer>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    monitorserver->EnableMonitor(pid);
}

void MonitorServerFuzzer::ObjCtrlFuzzTest(FuzzedDataProvider& provider)
{
    auto monitorserver = std::make_unique<MonitorServer>();
    size_t listSize = provider.ConsumeIntegralInRange<size_t>(0, ELEMENTS_MAX);
    auto recoveryList = std::list<wptr<MonitorServerObject>>();
    auto abnormalList = std::list<wptr<MonitorServerObject>>();
    for (size_t i = 0; i < listSize; i++) {
        if (provider.ConsumeBool()) {
            recoveryList.push_back(wptr<MonitorServerObject>(nullptr));
            abnormalList.push_back(wptr<MonitorServerObject>(nullptr));
        } else {
            sptr<MonitorServerObject> obj = sptr<MonitorServerObject>();
            if (obj != nullptr) {
                wptr<MonitorServerObject> weakObj = obj;
                abnormalList.push_back(weakObj);
                recoveryList.push_back(weakObj);
            }
        }
    }
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    monitorserver->EnableMonitor(pid);
}

void MonitorServerFuzzer::GetObjListByPidFuzzTest(FuzzedDataProvider& provider)
{
    auto monitorserver = std::make_unique<MonitorServer>();
    int32_t pid = provider.ConsumeIntegral<int32_t>();
    auto list = std::list<wptr<MonitorServerObject>>();
    size_t listSize = provider.ConsumeIntegralInRange<size_t>(0, ELEMENTS_MAX);
    for (size_t i = 0; i < listSize; i++) {
        if (provider.ConsumeBool()) {
            list.push_back(wptr<MonitorServerObject>(nullptr));
        } else {
            sptr<MonitorServerObject> obj = sptr<MonitorServerObject>();
            if (obj != nullptr) {
                wptr<MonitorServerObject> weakObj = obj;
                list.push_back(weakObj);
            }
        }
    }
    monitorserver->EnableMonitor(pid);
}

 /* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < MIN_SIZE_NUM) || (size > MAX_ALLOWED_SIZE)) {
        return 0;
    }
    FuzzedDataProvider provider(data, size);
 	/* Run your code on data */
    MonitorServerFuzzer::ClickFuzzTest(provider);
    MonitorServerFuzzer::GetTimeMSFuzzTest(provider);
    MonitorServerFuzzer::ObjCtrlFuzzTest(provider);
    MonitorServerFuzzer::GetObjListByPidFuzzTest(provider);
    return 0;
}
}
}