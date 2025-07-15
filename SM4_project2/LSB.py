#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LSB 空域水印示例（含攻击脚本）
----------------------------
1. embed_lsb()   : 将文本写入图像最低有效位
2. extract_lsb() : 从最低有效位恢复文本
3. 四种攻击函数    : 水平翻转、平移、中心裁剪、对比度拉伸
"""

import cv2
import numpy as np
import os

# -------------------- 嵌入函数 --------------------
def embed_lsb(src_path: str,
              secret: str,
              dst_path: str):
    """
    将字符串 secret 以 LSB 方式嵌入到 BGR 图像的 R 通道中。

    参数
    ----
    src_path : str
        原始图片路径
    secret   : str
        待隐藏的文本
    dst_path : str
        输出含水印图片路径（建议 png，避免 jpeg 再压缩破坏 LSB）
    """
    # 读取 BGR 图像
    img = cv2.imread(src_path)
    if img is None:
        raise FileNotFoundError(f'无法读取 {src_path}')

    # 将文本转为定长二进制串（每字符 8 位）
    bin_stream = ''.join(f'{ord(ch):08b}' for ch in secret)      # 例：'Hi' -> '0100100001101001'
    total_bits = len(bin_stream)

    # 只使用 R 通道，展平成一维向量方便逐像素处理
    r_channel = img[:, :, 2].flatten()

    if total_bits > r_channel.size:
        raise ValueError('文本过长，当前图像容量不足')

    # 逐位嵌入：把每个字节最低位替换为信息位
    for idx, bit in enumerate(bin_stream):
        pixel_val = r_channel[idx]
        # 0xFE = 11111110，先清零最低位，再或上目标比特
        r_channel[idx] = (pixel_val & 0xFE) | int(bit)

    # 将修改后的 R 通道写回并保存
    img[:, :, 2] = r_channel.reshape(img.shape[:2])
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    cv2.imwrite(dst_path, img)
    print(f'[+] 水印已嵌入并保存至 {dst_path}')

# -------------------- 提取函数 --------------------
def extract_lsb(img_path: str, text_len: int) -> str:
    """
    从 LSB 中提取隐藏文本。

    参数
    ----
    img_path : str
        含水印图片路径
    text_len : int
        原始文本字符长度（用于计算应取多少 bit）

    返回
    ----
    str
        恢复出的文本（若遭严重攻击可能包含乱码）
    """
    img = cv2.imread(img_path)
    if img is None:
        raise FileNotFoundError(f'无法读取 {img_path}')

    # 只取 R 通道
    r_channel = img[:, :, 2].flatten()
    need_bits = text_len * 8

    # 收集最低位
    bits = [str(r_channel[i] & 1) for i in range(need_bits)]

    # 每 8 位转成一个字符
    chars = []
    for i in range(0, len(bits), 8):
        byte = ''.join(bits[i:i+8])
        if len(byte) == 8:
            chars.append(chr(int(byte, 2)))
    return ''.join(chars)

# -------------------- 攻击函数 --------------------
def attack_flip(src: str, dst: str):
    """水平镜像翻转"""
    img = cv2.imread(src)
    cv2.imwrite(dst, cv2.flip(img, 1))

def attack_translate(src: str, dst: str, dx: int = 10, dy: int = 10):
    """平移攻击（空白处填黑）"""
    img = cv2.imread(src)
    h, w = img.shape[:2]
    M = np.float32([[1, 0, dx], [0, 1, dy]])
    cv2.imwrite(dst, cv2.warpAffine(img, M, (w, h)))

def attack_crop_resize(src: str, dst: str, ratio: float = 0.1):
    """中心裁剪后恢复原尺寸"""
    img = cv2.imread(src)
    h, w = img.shape[:2]
    dh, dw = int(h * ratio), int(w * ratio)
    cropped = img[dh:h - dh, dw:w - dw]
    cv2.imwrite(dst, cv2.resize(cropped, (w, h)))

def attack_contrast(src: str, dst: str, alpha: float = 1.5, beta: int = 0):
    """线性对比度拉伸"""
    img = cv2.imread(src)
    cv2.imwrite(dst, cv2.convertScaleAbs(img, alpha=alpha, beta=beta))

# -------------------- 演示 --------------------
if __name__ == '__main__':
    os.makedirs('data/attacks', exist_ok=True)

    ORIGINAL   = 'data/original.jpg'
    WATERMARK  = 'Hidden123'
    STEGO_FILE = 'data/stego.png'          # 建议用 png 保存 LSB 结果

    # 1. 嵌入
    embed_lsb(ORIGINAL, WATERMARK, STEGO_FILE)

    # 2. 施加攻击
    attack_flip(STEGO_FILE,      'data/attacks/flip.png')
    attack_translate(STEGO_FILE, 'data/attacks/trans.png')
    attack_crop_resize(STEGO_FILE, 'data/attacks/crop.png')
    attack_contrast(STEGO_FILE,   'data/attacks/contrast.png')

    # 3. 提取并打印
    print('提取结果（无攻击） :', extract_lsb(STEGO_FILE, len(WATERMARK)))
    print('提取结果（翻转）   :', extract_lsb('data/attacks/flip.png',    len(WATERMARK)))
    print('提取结果（平移）   :', extract_lsb('data/attacks/trans.png',   len(WATERMARK)))
    print('提取结果（裁剪）   :', extract_lsb('data/attacks/crop.png',    len(WATERMARK)))
    print('提取结果（对比度） :', extract_lsb('data/attacks/contrast.png', len(WATERMARK)))