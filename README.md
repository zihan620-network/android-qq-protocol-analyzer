<div align="center">

# Android QQ 协议自分析工具

**一键解析 APK、提取 Android QQ 协议参数**

本地离线解析 APK 文件，自动读取 `revision.txt` / `appid.ini` 与全部 DEX 字符串表，
输出协议请求所需的 `Apk_v`、`Ver`、`SdkVersion`、`Appid`、`BuildTime` 等参数，
JSON 结果一键复制，直接用于 QQ 协议调试。

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Tkinter](https://img.shields.io/badge/UI-Tkinter-0B5394?style=flat-square)
![PyInstaller](https://img.shields.io/badge/PyInstaller-6.x-darkgreen?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

</div>

---

## 📖 项目简介

`Android QQ 协议自分析工具` 是一个 Windows 桌面工具，用于从 Android QQ 安装包（APK）中
提取协议字段参数。不需要反编译、不需要 android SDK，纯本地离线运行，不联网、不上传任何数据。

将官方 APK 拖给工具 / 点击选择，即可在界面中直接看到结构化的 JSON 参数，
包含版本号、SDK 版本、Appid、构建时间、签名映射等，供协议调试 / 抓包分析 / 逆向学习使用。

## ✨ 功能特性

- 🚀 **一键解析**：选择 APK 后台线程解析，界面不卡顿
- 📦 **无需解压**：直接读取 ZIP 结构，临时文件零残留
- 🧬 **DEX 深度扫描**：解析全部 `classes*.dex` 字符串表（ULEB128 解码）
- 🎯 **多字段提取**：版本、SDK 版本、Appid、构建时间、哈希、mMiscBitmap 全覆盖
- 🖥️ **彩色 JSON 高亮**：键 / 字符串 / 数字分类着色，附完整调试信息
- 📋 **一键复制**：结果 JSON 直接进剪贴板
- 🔒 **本地离线**：纯本地解析，全程不联网

## 📦 输出字段

| 字段 | 说明 | 来源 |
| --- | --- | --- |
| `ApkId` | 包名 | `AndroidManifest.xml`（二进制 string pool） |
| `Apk_Sig` | APK 签名 | 固定值 |
| `App_Sig` | App 签名 | 固定值 |
| `Apk_v` | 版本号 `x.y.z` | `revision.txt` |
| `Apk_v_1` | 完整版本号 `x.y.z.w` | `revision.txt` / DEX 回退 |
| `Ver` | 协议内部版本 `A{x.y.z}.{hash}` | `revision.txt: internalVer` / DEX 回退 |
| `Appid` | 主协议 Appid | `appid.ini` |
| `Appid2` | 第二 Appid | `appid.ini` |
| `BuildTime` | 构建时间戳 | DEX 字符串 |
| `SdkVersion` | SDK 版本 `6.0.0.xxxx` | DEX 字符串（全量扫描） |
| `mMiscBitmap` | 位图参数 | DEX 字符串 |
| `_sub_appid_list` | 子 Appid 列表 | 固定值 |
| `_main_sig_map` | 主签名映射 | 固定值 |
| `SSOVersion` | SSO 协议版本 | 固定值 |
| `qr_v` | 二维码版本 | 固定值 |

### 解析规则细节

- **版本号**：优先读 `revision.txt` 的 `ver` / `Version`，其次匹配裸行 `x.y.z` / `x.y.z.w`
- **SDK 版本**：**仅**从全部 DEX 字符串表中搜索 `6.0.0.\d{4}` 模式，取最大值
- **Ver**：优先读 `revision.txt` 的 `internalVer`，再匹配 `A?x.y.z.xxxxxxxx` 裸行，
  最后回退为 `A{apk_v}.{dex 中 8 位哈希}`（已排除 `00000000` 等无效哈希）
- **Appid**：解析 `appid.ini` 中 `"appId": "..."` 字段，兼容 9 位纯数字行

## 🖥️ 界面预览

```
┌────────────────────────────────────────────┐
│  ■ Android QQ 协议自分析工具   By.JackHan    │
├────────────────────────────────────────────┤
│ [选择 APK] [复制 JSON] [清空]               │
│ 解析完成                                     │
│ ┌──────────────────────────────────────────┐ │
│ │ "ApkId": "com.tencent.mobileqq",        │ │
│ │ "Apk_Sig": "A6B745BF24A2C27752...",      │ │
│ │ "Apk_v": "9.3.50",                       │ │
│ │ "Ver": "A9.3.50.40125",                  │ │
│ │ "SdkVersion": "6.0.0.19",                │ │
│ │ ...                                       │ │
│ └──────────────────────────────────────────┘ │
└────────────────────────────────────────────┘
```

浅色护眼主题（`#f5f6fa` 背景 + 蓝色顶栏），绿色成功 / 红色错误状态提示。

## 🚀 快速开始

### 方式一：直接运行

下载 `dist/AndroidQQ协议自分析工具.exe`（Windows 10 / 11，无 Python 环境）：

```bash
dist\AndroidQQ协议自分析工具.exe
```

点「选择 APK」选中任意 Android QQ 安装包，或直接把 `.apk` 拖入界面即可。

### 方式二：源码运行

```bash
# 安装依赖（Tkinter 已随 Python 内置，无需额外安装）
pip install pyinstaller==6.22.2   # 仅打包时需要

# 运行
python apk_info_extractor_gui.py
```

## 📦 打包为 EXE

```bash
python -m PyInstaller --onefile --windowed --name "AndroidQQ" \
      --icon "icon.ico" --add-data "icon.ico;." \
      apk_info_extractor_gui.py --clean --noconfirm
```

打包后重命名为 `AndroidQQ协议自分析工具.exe` 即可分发（约 9MB，单文件、免安装）。

> 注意：PyInstaller 4.x / 6.x 已移除旧版 `--key` 字节码加密参数（官方认为密钥内嵌 EXE 无实际保护意义），


## ⚠️ 注意事项

- 本工具仅用于**学习交流与技术研究**，请勿用于任何违法用途
- 请遵守腾讯相关服务条款及当地法律法规
- 部分参数（`Apk_Sig`、`App_Sig`、`_main_sig_map` 等）为当前 QQ 版本固定值，版本更新后可能变化
- 若运行被杀毒软件拦截，请添加信任（PyInstaller 打包产物可能被误报）

## 📜 License

[MIT](LICENSE)
