# SM3 哈希算法实现与优化

## 项目概述

本项目致力于实现国密算法 **SM3 哈希函数** 的完整 C++ 版本。SM3 是由中国国家密码管理局发布的哈希标准（GM/T 0004-2012），在功能上与 SHA-256 类似，但算法结构和常量参数存在差异。

SM3 广泛应用于数字签名、消息认证码（MAC）、哈希验证等安全场景。

---

## 算法原理

SM3 的核心步骤如下：

- **消息填充（Padding）**
- **消息扩展（Message Expansion）：生成 W[68] 和 W′[64]**
- **压缩函数（Compression Function）：FF, GG, P0, P1 等**
- **输出摘要（Digest）：256 位（32 字节）**

每轮运算使用不同的常量 `Tj`，前 16 轮为 `0x79CC4519`，其余为 `0x7A879D8A`。

---

## 项目功能与优化

### 功能特性

- 支持输入字符串或 `uint8_t` 字节数组进行哈希计算
- 输出为 `std::vector<uint8_t>`，可转换为十六进制字符串
- 包含官方测试用例，用于验证正确性

### 优化细节

| 优化项 | 描述 |
|--------|------|
| 使用 `std::array` | 替代裸数组，提升安全性和可读性 |
| 使用 `constexpr` | 对常量参数进行编译期处理，提升性能 |
| 使用现代 C++ 语法 | 采用结构化绑定、范围 for、`static_cast` 等 |
| 结构清晰 | 函数划分合理，逻辑清晰，便于维护 |
| 易于扩展 | 可作为其他密码系统（如 SM2）的基础模块 |

---

## 文件结构

```
├── SM3.cpp # SM3 算法核心实现与测试用例
├── SM3_.cpp # 优化后的 SM3 算法
```

---

## 编译与运行

- 支持 C++11 及以上版本的编译器（如 g++, clang++, MSVC）
- 不依赖外部库，无需 CMake，直接编译即可


## 结果输出

```
Input: "abc"
Output: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
Expected: 66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
Match: 1

Input: "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
Output: debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
Expected: debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
Match: 1

Input: "HelloSM3"
Output: 36065686c1859012d3b504ecee7ae52e5f0fdf3089a0854811f613f77599a4cd
Expected: 36065686c1859012d3b504ecee7ae52e5f0fdf3089a0854811f613f77599a4cd
Match: 1
```

## 具体优化思路

| 优化点             | 原始实现                         | 优化后实现                                       | 优化效果                  |
|-------------------|--------------------------------|----------------------------------------------|------------------------|
| 数据结构安全性      | `uint32_t V[8]`，裸数组        | `std::array<uint32_t, 8> V`                 | 提升类型安全，支持 STL 接口，便于维护 |
| 常量表达          | `#define`/常量函数手写         | `constexpr size_t BLOCK_SIZE = 64`等        | 编译期优化，减少魔法数字          |
| 内联函数管理      | 函数未标注`static`或`constexpr` | 所有辅助函数标为`static`或`constexpr`       | 编译器内联优化，减少链接开销       |
| 宏替换为函数      | 无                              | 用`constexpr T(j)`取代宏定义                | 避免宏副作用，增强可读性          |
| 类型转换安全      | 使用`int b = bytes[i]`         | 明确使用`static_cast`                       | 减少隐式转换导致的错误，提升安全性   |
| STL 语法使用       | 原始for循环+下标                | 使用`range-based for`+`structured binding` | 更现代，更简洁，可读性更强         |
| 异常安全          | 全部裸指针操作                   | 使用`std::vector`和`std::array`管理资源      | 减少内存泄漏风险，更安全          |
| 结构组织          | 所有函数堆在一起，少用私有封装     | 结构清晰，私有函数明确封装                    | 便于后期维护和测试           |
| 魔法数字清理      | 到处写了`64`,`32`等            | 使用`BLOCK_SIZE`,`DIGEST_SIZE`等命名常量    | 提高可读性和灵活性           |
| 输出组织          | 分散的输出逻辑                   | 使用结构化输出、表格显示测试结果              | 可读性强，便于与测试数据对比       |

---