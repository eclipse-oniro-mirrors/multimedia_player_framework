---
name: unit-test
description: Enforce proper unit test practices - use GTest/GMock, follow project test naming conventions, achieve adequate coverage, mock external dependencies
---

# Unit Test Skill

This skill enforces proper unit test practices for the OpenHarmony media framework.

## Test Framework Setup

### Required Dependencies

```python
# In BUILD.gn
external_deps = [
    "googletest:gtest_main",
    "googletest:gmock_main",
    "hilog:libhilog",
    "c_utils:utils",
]
```

### Test Class Structure

```cpp
namespace OHOS {
namespace Media {
namespace MediaDownload {

class DownloaderImplUnitTest : public testing::Test {
public:
    static void SetUpTestCase(void);    // Called before all tests
    static void TearDownTestCase(void);  // Called after all tests
    void SetUp(void);                   // Called before each test
    void TearDown(void);                // Called after each test
    
    std::shared_ptr<Downloader> downloader_;
    std::shared_ptr<MockDownloadCallback> callback_;
};

}  // namespace MediaDownload
}  // namespace Media
}  // namespace OHOS
```

## Test Naming Convention

### Test Function Naming

```cpp
/**
 * @tc.name    : Test SetUrl API
 * @tc.number  : SetUrl_001
 * @tc.desc    : Test SetUrl interface with valid http URL
 * @tc.require : issueI5NZAQ
 */
HWTEST_F(DownloaderImplUnitTest, SetUrl_001, TestSize.Level0)
{
    std::string url = "http://example.com/file.bin";
    int32_t ret = downloader_->SetUrl(url);
    EXPECT_EQ(ret, DOWNLOAD_ERROR_OK);
}
```

### Naming Format

| Element | Format | Example |
|---------|--------|---------|
| Test class | `<Class>UnitTest` | `DownloaderImplUnitTest` |
| Test function | `<Method>_<Number>` | `SetUrl_001` |
| Test macro | `HWTEST_F` | `HWTEST_F(Class, Method_001, Level)` |
| Test level | `TestSize.Level0/Level1/Level2` | `TestSize.Level0` |

### Comment Header Format

```cpp
/**
 * @tc.name    : <Test description>
 * @tc.number  : <TestFunctionName>
 * @tc.desc    : <Detailed test description>
 * @tc.require : <Issue number or requirement ID>
 */
```

## Test Levels

| Level | Meaning | Usage |
|-------|---------|-------|
| Level0 | Critical functionality | Core features, must pass |
| Level1 | Important functionality | Major features |
| Level2 | General functionality | Minor features, edge cases |

## Mock Classes

### Mock Definition Pattern

```cpp
#include <gmock/gmock.h>

class MockDownloadCallback : public DownloadCallback {
public:
    MOCK_METHOD(void, OnStateChanged, (DownloadState state));
    MOCK_METHOD(void, OnCompleted, (int64_t downloadedSize));
    MOCK_METHOD(void, OnFailed, (DownloadErrorType, int32_t, const std::string&));
    MOCK_METHOD(void, OnProgress, (const DownloadProgress&));
};

class MockNetworkClient {
public:
    MOCK_METHOD(int32_t, Connect, ());
    MOCK_METHOD(void, Disconnect, ());
    MOCK_METHOD(int32_t, Read, (uint8_t*, int32_t, int32_t&));
    MOCK_METHOD(int64_t, GetTotalSize, ());
    MOCK_METHOD(bool, IsConnected, ());
};
```

### Mock Location

Place mock classes in:
- `test/unittest/<module>_unittest/mock/` directory
- Or in test header file for simple mocks

## Test Writing Patterns

### Pattern 1: Basic Verification

```cpp
HWTEST_F(DownloaderImplUnitTest, Create_001, TestSize.Level0)
{
    auto downloader = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader, nullptr);
    EXPECT_EQ(downloader->GetState(), DOWNLOAD_IDLE);
}
```

### Pattern 2: Parameter Validation

```cpp
HWTEST_F(DownloaderImplUnitTest, SetUrl_001, TestSize.Level0)
{
    std::string emptyUrl = "";
    int32_t ret = downloader_->SetUrl(emptyUrl);
    EXPECT_EQ(ret, DOWNLOAD_ERROR_INVALID_PARAM);
}

HWTEST_F(DownloaderImplUnitTest, SetUrl_002, TestSize.Level0)
{
    std::string validUrl = "http://example.com/file.bin";
    int32_t ret = downloader_->SetUrl(validUrl);
    EXPECT_EQ(ret, DOWNLOAD_ERROR_OK);
}
```

### Pattern 3: State Transition

```cpp
HWTEST_F(DownloaderImplUnitTest, Start_001, TestSize.Level0)
{
    downloader_->SetUrl("http://test.com/file.bin");
    downloader_->SetOutputPath("/tmp/test.bin");
    
    int32_t ret = downloader_->Start();
    EXPECT_EQ(ret, DOWNLOAD_ERROR_OK);
    EXPECT_EQ(downloader_->GetState(), DOWNLOAD_PREPARING);
}

HWTEST_F(DownloaderImplUnitTest, Start_002, TestSize.Level0)
{
    int32_t ret = downloader_->Start();  // No URL set
    EXPECT_EQ(ret, DOWNLOAD_ERROR_NOT_SET_URL);
}
```

### Pattern 4: Mock Callback Verification

```cpp
HWTEST_F(DownloaderImplUnitTest, Callback_001, TestSize.Level0)
{
    auto callback = std::make_shared<MockDownloadCallback>();
    downloader_->SetDownloadCallback(callback);
    
    EXPECT_CALL(*callback, OnStateChanged(DOWNLOAD_PREPARING))
        .Times(1);
    EXPECT_CALL(*callback, OnStateChanged(DOWNLOAD_RUNNING))
        .Times(AtLeast(1));
    
    downloader_->SetUrl("http://test.com/file.bin");
    downloader_->SetOutputPath("/tmp/test.bin");
    downloader_->Start();
}
```

### Pattern 5: Mock Dependency Behavior

```cpp
HWTEST_F(DownloadTaskUnitTest, ConnectSuccess_001, TestSize.Level0)
{
    MockNetworkClient mockClient;
    
    EXPECT_CALL(mockClient, Connect())
        .WillOnce(Return(DOWNLOAD_ERROR_OK));
    EXPECT_CALL(mockClient, GetTotalSize())
        .WillRepeatedly(Return(10000));
    
    // Inject mock and test
}
```

## Expectation Types

### ASSERT vs EXPECT

| Macro | Behavior | Use When |
|-------|----------|----------|
| `ASSERT_*` | Fails and stops test | Pre-condition critical |
| `EXPECT_*` | Fails and continues | Check multiple conditions |

```cpp
HWTEST_F(Test, Example, TestSize.Level0)
{
    ASSERT_NE(ptr, nullptr);  // If null, stop immediately
    EXPECT_EQ(ptr->GetValue(), 10);  // Check value
    EXPECT_EQ(ptr->GetStatus(), OK);  // Check status (both checked even if first fails)
}
```

### Common Macros

```cpp
EXPECT_EQ(actual, expected);     // Equal
EXPECT_NE(actual, expected);     // Not equal
EXPECT_LT(actual, expected);     // Less than
EXPECT_LE(actual, expected);     // Less or equal
EXPECT_GT(actual, expected);     // Greater than
EXPECT_GE(actual, expected);     // Greater or equal
EXPECT_TRUE(condition);
EXPECT_FALSE(condition);
EXPECT_STREQ(str1, str2);        // String equal
EXPECT_FLOAT_EQ(f1, f2);         // Float equal (approximate)
EXPECT_DOUBLE_EQ(d1, d2);        // Double equal (approximate)
```

## Mock Expectations

### Basic EXPECT_CALL

```cpp
EXPECT_CALL(mockObject, Method(paramMatcher))
    .Times(cardinality)
    .WillOnce(Return(value));
```

### Cardinality

| Cardinality | Meaning |
|-------------|---------|
| `Times(1)` | Called exactly once |
| `Times(2)` | Called exactly twice |
| `Times(AtLeast(1))` | Called 1 or more times |
| `Times(AtMost(3))` | Called 3 or fewer times |
| `Times(AnyNumber())` | Called any number of times |
| `Times(0)` | Never called |

### Parameter Matchers

```cpp
EXPECT_CALL(mock, Method(_));              // Any value
EXPECT_CALL(mock, Method(Eq(10)));         // Equal to 10
EXPECT_CALL(mock, Method(Gt(0)));          // Greater than 0
EXPECT_CALL(mock, Method(Lt(100)));        // Less than 100
EXPECT_CALL(mock, Method(StrEq("test")));  // String equal
```

### Action Types

```cpp
WillOnce(Return(value));                   // Return value
WillOnce(ReturnByMove(value));             // Return by move
WillRepeatedly(Return(value));             // Return value each call
WillOnce(Invoke([]() { return 10; }));     // Call lambda
WillOnce(SetArgPointee<0>(value));         // Set output parameter
```

## Test Coverage

### Coverage Requirements

| Level | Requirement |
|-------|-------------|
| Core functions | 100% coverage |
| Important functions | ≥80% coverage |
| General functions | ≥60% coverage |

### Coverage Types

| Coverage Type | What to Check |
|---------------|---------------|
| Line coverage | Each line executed |
| Branch coverage | Each branch taken |
| Function coverage | Each function called |
| Statement coverage | Each statement executed |

## Test Structure Best Practices

### 1. Setup in SetUp

```cpp
void DownloaderImplUnitTest::SetUp(void)
{
    downloader_ = DownloaderFactory::CreateDownloader();
    ASSERT_NE(downloader_, nullptr);
    callback_ = std::make_shared<MockDownloadCallback>();
}
```

### 2. Cleanup in TearDown

```cpp
void DownloaderImplUnitTest::TearDown(void)
{
    if (downloader_) {
        downloader_->Release();
        downloader_ = nullptr;
    }
    callback_ = nullptr;
}
```

### 3. One Assertion per Concept

```cpp
HWTEST_F(Test, Example, TestSize.Level0)
{
    int32_t ret = downloader_->Start();
    EXPECT_EQ(ret, DOWNLOAD_ERROR_OK);
    
    DownloadState state = downloader_->GetState();
    EXPECT_EQ(state, DOWNLOAD_PREPARING);
    
    uint64_t taskId = downloader_->GetCurrentTaskId();
    EXPECT_NE(taskId, INVALID_TASK_ID);
}
```

### 4. Test Independent

Each test should be independent, not rely on other tests' results.

## Project Test Structure

### Directory Layout

```
test/unittest/net_downloader_unittest/
├── downloader_impl_unit_test.h
├── downloader_impl_unit_test.cpp
├── download_task_unit_test.cpp
├── message_queue_unit_test.cpp
├── mock/
│   ├── mock_download_callback.h
│   ├── mock_network_client.h
│   └ mock_file_writer.h
└── BUILD.gn
```

### BUILD.gn Template

```python
import("//build/test.gni")
import("//foundation/multimedia/player_framework/config.gni")

module_output_path = "player_framework/player_framework/net_downloader"

config("test_config") {
  visibility = [ ":*" ]
  cflags = [ "-O2", "-fPIC", "-Wall", "-fexceptions" ]
  include_dirs = [
    "$MEDIA_ROOT_DIR/services/services/media_source/net_downloader",
    "$MEDIA_ROOT_DIR/services/utils/include",
  ]
}

ohos_unittest("net_downloader_unit_test") {
  module_out_path = module_output_path
  sources = [ "downloader_impl_unit_test.cpp" ]
  configs = [ ":test_config" ]
  external_deps = [
    "googletest:gtest_main",
    "googletest:gmock_main",
    "hilog:libhilog",
  ]
}
```

## Running Tests

### Build Command

```bash
./build.sh --product-name <product> --build-target net_downloader_unit_test
```

### Run Test Binary

```bash
cd out/<product>/tests/unittest/player_framework/net_downloader
./net_downloader_unit_test
```

### Run Specific Test

```bash
./net_downloader_unit_test --gtest_filter=DownloaderImplUnitTest.SetUrl_001
```

### Generate Coverage

```bash
./net_downloader_unit_test --gtest_output=xml:test_results.xml
lcov --capture --directory . --output-file coverage.info
```

## Summary Checklist

| Check | Requirement |
|-------|-------------|
| Test class | `<Class>UnitTest` naming |
| Test function | `HWTEST_F(Class, Method_001, Level)` |
| Comment header | @tc.name, @tc.number, @tc.desc |
| Mock classes | In mock/ directory or test header |
| Setup/TearDown | Initialize in SetUp, cleanup in TearDown |
| Assertions | ASSERT for critical, EXPECT for checks |
| Coverage | ≥80% for important functions |
| Independence | Tests don't depend on each other |