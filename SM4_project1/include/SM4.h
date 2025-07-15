/**
 * @file SM4.h
 * @brief 国密 SM4 分组密码算法头文件（重写注释与命名，功能不变）
 * @license MIT
 */

#ifndef SM4_REWRITTEN_H
#define SM4_REWRITTEN_H

#include <vector>
#include <cstdint>
#include <stdexcept>

class SM4 {
public:
    /**
     * @brief 构造函数：使用 128bit（16Byte）密钥初始化 SM4 对象
     * @param userKey 16 字节密钥
     * @throw std::invalid_argument 密钥长度不为 16 字节时抛出
     */
    explicit SM4(const std::vector<uint8_t>& userKey);

    /**
     * @brief ECB 模式加密接口
     * @param plain 明文数据，长度必须是 16 的整数倍
     * @return 加密后的密文
     */
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plain);

    /**
     * @brief ECB 模式解密接口
     * @param cipher 密文数据，长度必须是 16 的整数倍
     * @return 解密后的明文
     */
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& cipher);

private:
    /* 32 轮轮密钥 */
    uint32_t roundKey[32];

    /* ---------------- 内部辅助函数 ---------------- */
    void expandKey(const std::vector<uint8_t>& key);          // 密钥扩展
    uint32_t roundFunc(uint32_t a, uint32_t b,
                       uint32_t c, uint32_t d, uint32_t rk);  // 轮函数 F
    uint32_t nonLinear(uint32_t x);                           // 合成置换 T
    uint32_t nonLinearKey(uint32_t x);                        // 密钥扩展专用置换 T'
    uint32_t linearL(uint32_t b);                             // 线性变换 L
    uint32_t linearLK(uint32_t b);                            // 密钥扩展专用线性变换 L'
    uint32_t rotl(uint32_t w, uint32_t n);                    // 32 位循环左移
    std::vector<uint8_t> cryptCore(const std::vector<uint8_t>& in, bool enc);

    /* 常量区：S盒、系统参数 FK、固定参数 CK */
    static const uint8_t  SBOX[256];
    static const uint32_t FK[4];
    static const uint32_t CK[32];
};

#endif // SM4_REWRITTEN_H