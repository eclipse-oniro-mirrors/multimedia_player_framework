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

#include "mock_session_manager_lite_injector.h"
#include "mock_remote_object.h"
#include "session_manager_lite.h"

namespace OHOS {
namespace Media {

sptr<Rosen::MockSceneSessionManagerLite> InjectMockSceneSessionManagerLite()
{
    using ::testing::_;
    using ::testing::Return;
    auto &ssm = Rosen::SessionManagerLite::GetInstance();
    auto mock = sptr<Rosen::MockSceneSessionManagerLite>::MakeSptr();
    auto remoteObj = sptr<MockRemoteObject>::MakeSptr();
    ON_CALL(*mock, AsObject()).WillByDefault(Return(remoteObj));
    ON_CALL(*mock, RegisterSessionLifecycleListenerByIds(_, _)).WillByDefault(Return(Rosen::WMError::WM_OK));
    ON_CALL(*mock, UnregisterSessionLifecycleListener(_)).WillByDefault(Return(Rosen::WMError::WM_OK));
    ON_CALL(*mock, RegisterSessionLifecycleListenerByAppInstance(_, _, _, _))
        .WillByDefault(Return(Rosen::WMError::WM_OK));
    ssm.sceneSessionManagerLiteProxy_ = mock;
    ssm.sessionManagerServiceProxy_ = sptr<DummySessionManagerService>::MakeSptr();
    return mock;
}

void ClearMockSceneSessionManagerLite()
{
    auto &ssm = Rosen::SessionManagerLite::GetInstance();
    ssm.sceneSessionManagerLiteProxy_ = nullptr;
    ssm.sessionManagerServiceProxy_ = nullptr;
}

} // namespace Media
} // namespace OHOS
