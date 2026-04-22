# C# RSA Encryption Implementation & Tests

Production-ready C# implementation and comprehensive test suite for secure RSA encryption with OAEP padding, designed for server-side decryption of data from the Cordova mobile plugin.

## 📂 Folder Structure

```
examples/server/csharp/
├── README.md                          (This file)
├── RSAEncryptionHelper.cs             (Main implementation - 60 LOC)
├── RSAEncryptionHelperTests.cs        (27 comprehensive test cases - 450 LOC)
├── RSAEncryptionHelperTests.csproj    (MSTest configuration)
```

## 🚀 Quick Start

### 1. Build the Project
```bash
cd examples/server/csharp
dotnet restore
dotnet build
```

**Actual Output:**
```
Restore complete (0.2s)
Build succeeded in 0.4s
0 Warning(s)
0 Error(s)
```

### 2. Run All Tests
```bash
dotnet test --verbosity normal
```

**Actual Result:**
```
Test Run Successful.
Total tests: 27
Passed: 27
Failed: 0
Time: 1.1638 seconds

Build succeeded.
0 Warning(s)
0 Error(s)
Time Elapsed 00:00:01.80
```
