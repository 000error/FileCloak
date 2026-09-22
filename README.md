# FileCloak

Windows 文件加密小工具 —— 原地加密，文件名与格式保持不变，打开即是"乱码"。

## 特性

- **AES-256-GCM**：加密 + 完整性校验，密码错误会明确提示，不会解出乱码
- **PBKDF2-HMAC-SHA256** 密码派生密钥：600,000 次迭代 + 每文件独立随机盐
- **原地加密**：文件名、扩展名完全不变，文件内容变为随机字节，直接打开显示乱码
- **批量处理**：图形界面与命令行均支持多文件，自动跳过已加密/未加密文件
- **防重复加密**：已加密文件无法再次加密（界面置灰 + 核心函数拦截）
- **原子写入**：临时文件 + 替换，中途出错不损坏原文件

## 加密文件格式

```
[4B 魔数 "FLE1"][16B 盐][12B Nonce][密文 + GCM Tag]
```

## 使用

### 图形界面

双击 `FileCloak.exe`，或：

```
python filecloak.py
```

添加文件（可多选）→ 输入密码 → 加密 / 解密。点击列表中的文件时，
按钮会按其加密状态自动启用/置灰；不选文件则默认处理整个列表。

### 命令行

```
python filecloak.py -e 文件1 文件2 ...    # 批量加密
python filecloak.py -d 文件1 文件2 ...    # 批量解密
```

## 打包 exe

```
pip install pyinstaller cryptography
pyinstaller -F -w -n FileCloak filecloak.py
```

产物在 `dist/FileCloak.exe`。

## 依赖

- Python 3.8+
- [cryptography](https://pypi.org/project/cryptography/)

## ⚠️ 注意

- **密码无法找回**：忘记密码 = 文件永久无法解密，请务必牢记
- 加密会直接覆盖原文件，重要文件建议先备份
- 文件整体读入内存加密，超大文件（数 GB）会占用较多内存
