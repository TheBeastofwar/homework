#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Robust DCT Blind Watermarking
-----------------------------
1. 嵌入：将文本水印转为二进制，借助 8×8 DCT 块中两个中频系数之差隐藏比特。
2. 提取：利用多数投票机制恢复比特流，再转回文字。
3. 鲁棒性：通过冗余嵌入 + 投票对抗常见攻击（翻转、平移、裁剪、对比度拉伸）。

依赖：
    pip install opencv-python numpy
"""

import cv2
import numpy as np
from collections import Counter
import random
import os

# -------------------- 工具函数 --------------------
def _block_dct(block: np.ndarray) -> np.ndarray:
    """对单个 8×8 块做 DCT 变换，返回 float32 类型系数矩阵"""
    return cv2.dct(np.float32(block))

def _block_idct(dct_mat: np.ndarray) -> np.ndarray:
    """对 DCT 系数矩阵做逆变换，返回 float32 像素块"""
    return cv2.idct(dct_mat)

def _text_to_bits(text: str) -> str:
    """将任意字符串转换为二进制字符串（每字符 8 位，UTF-8 编码）"""
    return ''.join(f'{ord(ch):08b}' for ch in text)

def _bits_to_text(bits: str) -> str:
    """将二进制字符串转回文本"""
    chars = [bits[i:i + 8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(b, 2)) for b in chars if len(b) == 8)

# -------------------- 嵌入函数 --------------------
def embed_watermark_robust(src_img_path: str,
                           message: str,
                           dst_img_path: str,
                           block_size: int = 8,
                           redundancy: int = 3,
                           strength: float = 5.0,
                           seed: int = 42):
    """
    将 message 嵌入到灰度图像的 DCT 系数中。

    参数
    ----
    src_img_path : str
        原始灰度图像路径
    message : str
        待嵌入文本
    dst_img_path : str
        含水印图像保存路径
    block_size : int
        DCT 分块大小，默认 8
    redundancy : int
        每个比特冗余嵌入的次数，默认 3
    strength : float
        修改强度，默认 5.0
    seed : int
        随机种子，用于固定嵌入顺序
    """
    img = cv2.imread(src_img_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise FileNotFoundError(f'Cannot open {src_img_path}')

    h, w = img.shape
    bits = _text_to_bits(message)
    bits_len = len(bits)

    max_blocks = (h // block_size) * (w // block_size)
    need_blocks = bits_len * redundancy
    if need_blocks > max_blocks:
        raise ValueError('图像过小，无法容纳水印')

    # 生成所有 8×8 块的左上角坐标并按随机顺序排列
    coords = [(r, c)
              for r in range(0, h - block_size + 1, block_size)
              for c in range(0, w - block_size + 1, block_size)]
    random.seed(seed)
    random.shuffle(coords)

    # 待嵌入的两个系数坐标
    pos_a, pos_b = (3, 2), (2, 3)  # 中频

    watermarked = img.astype(np.float32)
    coord_idx = 0

    for bit in bits:
        for _ in range(redundancy):
            y, x = coords[coord_idx]
            block = watermarked[y:y + block_size, x:x + block_size]
            dct = _block_dct(block)

            coeff_a, coeff_b = dct[pos_a], dct[pos_b]
            if int(bit) == 1 and coeff_a <= coeff_b:
                dct[pos_a] = coeff_b + strength
            elif int(bit) == 0 and coeff_a >= coeff_b:
                dct[pos_b] = coeff_a + strength

            watermarked[y:y + block_size, x:x + block_size] = np.clip(
                _block_idct(dct), 0, 255)
            coord_idx += 1

    os.makedirs(os.path.dirname(dst_img_path), exist_ok=True)
    cv2.imwrite(dst_img_path, watermarked.astype(np.uint8))
    print(f'[Embed] 水印已写入 {dst_img_path}')

# -------------------- 提取函数 --------------------
def extract_watermark_robust(wm_img_path: str,
                             msg_len: int,
                             block_size: int = 8,
                             redundancy: int = 3,
                             seed: int = 42,
                             threshold: float = 1.0) -> str:
    """
    从含水印图像中提取文本。

    参数
    ----
    wm_img_path : str
        含水印图像路径
    msg_len : int
        原始文本长度（字符数）
    block_size, redundancy, seed, threshold
        与嵌入时保持一致

    返回
    ----
    str
        提取出的文本
    """
    img = cv2.imread(wm_img_path, cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise FileNotFoundError(f'Cannot open {wm_img_path}')

    h, w = img.shape
    bits_len = msg_len * 8
    total_samples = bits_len * redundancy

    coords = [(r, c)
              for r in range(0, h - block_size + 1, block_size)
              for c in range(0, w - block_size + 1, block_size)]
    random.seed(seed)
    random.shuffle(coords)

    pos_a, pos_b = (3, 2), (2, 3)
    recovered_bits = []

    for i in range(bits_len):
        votes = []
        for j in range(redundancy):
            idx = i * redundancy + j
            if idx >= len(coords):
                break
            y, x = coords[idx]
            block = img[y:y + block_size, x:x + block_size].astype(np.float32)
            dct = _block_dct(block)
            diff = dct[pos_a] - dct[pos_b]

            if abs(diff) < threshold:
                continue  # 差距太小视为不可靠
            votes.append(1 if diff > 0 else 0)

        # 多数投票
        if votes:
            recovered_bits.append(str(Counter(votes).most_common(1)[0][0]))
        else:
            recovered_bits.append('0')  # 默认 0

    return _bits_to_text(''.join(recovered_bits))

# -------------------- 攻击函数 --------------------
def _flip_horizontally(src_path: str, dst_path: str):
    """水平翻转攻击"""
    img = cv2.imread(src_path)
    cv2.imwrite(dst_path, cv2.flip(img, 1))

def _translate(src_path: str, dst_path: str, tx=10, ty=10):
    """平移攻击"""
    img = cv2.imread(src_path)
    rows, cols = img.shape[:2]
    M = np.float32([[1, 0, tx], [0, 1, ty]])
    cv2.imwrite(dst_path, cv2.warpAffine(img, M, (cols, rows)))

def _crop_and_resize(src_path: str, dst_path: str, ratio=0.1):
    """中心裁剪后恢复尺寸"""
    img = cv2.imread(src_path)
    h, w = img.shape[:2]
    dh, dw = int(h * ratio), int(w * ratio)
    cropped = img[dh:h - dh, dw:w - dw]
    cv2.imwrite(dst_path, cv2.resize(cropped, (w, h)))

def _contrast_stretch(src_path: str, dst_path: str, alpha=1.5, beta=0):
    """对比度拉伸攻击"""
    img = cv2.imread(src_path)
    cv2.imwrite(dst_path, cv2.convertScaleAbs(img, alpha=alpha, beta=beta))

# -------------------- 主流程演示 --------------------
if __name__ == '__main__':
    ORIGINAL = 'data/original.jpg'
    WM_IMG   = 'data/watermarked.jpg'
    WM_TEXT  = 'Hidden123'

    # 1. 嵌入
    embed_watermark_robust(ORIGINAL, WM_TEXT, WM_IMG)

    # 2. 直接提取
    print('[Extract] 无攻击：', extract_watermark_robust(WM_IMG, len(WM_TEXT)))

    # 3. 攻击并提取
    os.makedirs('data/attacks', exist_ok=True)
    _flip_horizontally(WM_IMG, 'data/attacks/flip.jpg')
    _translate(WM_IMG, 'data/attacks/translate.jpg')
    _crop_and_resize(WM_IMG, 'data/attacks/crop.jpg')
    _contrast_stretch(WM_IMG, 'data/attacks/contrast.jpg')

    print('[Extract] 翻转后：', extract_watermark_robust('data/attacks/flip.jpg', len(WM_TEXT)))
    print('[Extract] 平移后：', extract_watermark_robust('data/attacks/translate.jpg', len(WM_TEXT)))
    print('[Extract] 裁剪后：', extract_watermark_robust('data/attacks/crop.jpg', len(WM_TEXT)))
    print('[Extract] 对比度拉伸后：', extract_watermark_robust('data/attacks/contrast.jpg', len(WM_TEXT)))