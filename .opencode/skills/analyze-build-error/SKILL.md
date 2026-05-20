---
name: analyze-build-error
description: Analyze OpenHarmony build errors and provide solutions
license: Apache-2.0
compatibility: opencode
metadata:
  audience: developers
  language: cpp
  framework: openharmony
---

## What I do

I analyze OpenHarmony build errors from compilation logs and provide actionable solutions to fix them.

## When to use me

Use this when you need to:
- Analyze compilation failures from build logs
- Understand what went wrong during the build process
- Get suggestions for fixing compilation errors
- Extract specific error messages and warnings from large build logs

## Build Log Location

Build log is located at `<ohos_root>/out/rk3568/build.log`

OpenHarmony root directory can be found by locating `.repo/` directory:

```bash
# Detect OpenHarmony root directory
dir="$(pwd)"
while [[ "$dir" != "/" ]]; do
    if [[ -d "$dir/.repo" ]]; then
        echo "$dir"
        break
    fi
    dir="$(dirname "$dir")"
done
```

## How to use me

Invoke with optional path parameter:
```
/analyze-build-error                    # Auto-detect log location
/analyze-build-error /path/to/log.log  # Specify exact path
```

I will:
1. Detect OpenHarmony root by finding `.repo/` directory
2. Locate the build log (from parameter or `<ohos_root>/out/rk3568/build.log`)
3. Read and parse the log
4. Extract all compilation errors
5. Categorize the errors
6. Provide specific fix recommendations

## Common Error Patterns

### 1. Type Name Errors
```
error: unknown type name 'TypeName'
```
**Cause**: Missing header include or incorrect namespace
**Solution**: Check if the header file is included and verify namespace usage

### 2. Member Not Found Errors
```
error: no member named 'MemberName' in 'ClassName'
```
**Cause**: API changes or incorrect member name
**Solution**: Check the class definition for correct member names

### 3. Undeclared Identifier Errors
```
error: use of undeclared identifier 'IDENTIFIER'
```
**Cause**: Missing declaration or variable out of scope
**Solution**: Add proper includes or check variable scope

### 4. Constructor Initialization Errors
```
error: member initializer 'member_' does not name a non-static data member
```
**Cause**: Typo in member name or member does not exist
**Solution**: Check class member names match initialization list

### 5. Field Initialization Order Warnings
```
error: field 'a' will be initialized after field 'b' [-Werror,-Wreorder-ctor]
```
**Cause**: Initialization order does not match declaration order
**Solution**: Reorder initialization list to match declaration order

## Error Extraction Strategy

I use the following grep patterns to identify errors:
- `error:` - Main error marker
- `fatal error:` - Fatal errors
- `FAILED:` - Build target failures
- `-Werror` - Warnings treated as errors

## Analysis Process

1. **Extract Error Context**: Read lines around each error for context
2. **Identify Root Cause**: Determine the underlying issue
3. **Check Related Files**: Read source files mentioned in errors
4. **Provide Solutions**: Suggest specific code changes

## Example Commands

```bash
# Use auto-detection
/analyze-build-error

# Specify custom path
/analyze-build-error /tmp/my_build.log
```

## Output Format

I will provide:
1. **Error Summary**: Number and types of errors
2. **Detailed Errors**: Each error with file location and line number
3. **Root Cause Analysis**: What caused the errors
4. **Fix Recommendations**: Specific code changes needed

## Best Practices

1. Always check header includes when seeing type errors
2. Verify API compatibility after framework updates
3. Pay attention to warning errors (-Werror flags)
4. Check namespace and scope for identifier errors
5. Ensure member names match between declarations and definitions