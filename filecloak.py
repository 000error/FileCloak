# -*- coding: utf-8 -*-
"""
FileCloak — 文件加密/解密小工具 (Windows)

特性:
  - AES-256-GCM 加密(机密性 + 完整性校验)
  - PBKDF2-HMAC-SHA256 密码派生密钥 (600,000 次迭代)
  - 原地加密: 文件名/扩展名不变, 文件打开显示为乱码
  - 图形界面 (tkinter, Python 自带), 同时支持命令行

文件格式 (加密后):
  [4B 魔数 "FLE1"][16B 盐][12B Nonce][密文+GCM Tag]

用法:
  双击运行 或  python filecloak.py              -> 图形界面
  python filecloak.py -e 文件1 文件2 ...         -> 命令行批量加密
  python filecloak.py -d 文件1 文件2 ...         -> 命令行批量解密
"""

import os
import sys
import argparse
import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC = b"FLE1"          # 4 字节魔数, 用于识别文件是否已加密
SALT_LEN = 16
NONCE_LEN = 12
KDF_ITERATIONS = 600_000
HEADER_LEN = len(MAGIC) + SALT_LEN + NONCE_LEN  # 32 字节


def derive_key(password: str, salt: bytes) -> bytes:
    """从密码派生 256 位密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def is_encrypted(path: str) -> bool:
    """判断文件是否已是本工具加密过的"""
    try:
        with open(path, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def _atomic_write(path: str, data: bytes):
    """先写临时文件再替换, 避免中途出错损坏原文件"""
    tmp = path + ".tmp_fle"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def encrypt_file(path: str, password: str):
    """原地加密文件 (文件名/扩展名不变)"""
    if is_encrypted(path):
        raise ValueError("该文件已经是加密状态, 无需重复加密")

    with open(path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    _atomic_write(path, MAGIC + salt + nonce + ciphertext)


def decrypt_file(path: str, password: str):
    """原地解密文件"""
    with open(path, "rb") as f:
        data = f.read()

    if data[:len(MAGIC)] != MAGIC:
        raise ValueError("该文件不是本工具加密的文件")

    salt = data[4:4 + SALT_LEN]
    nonce = data[4 + SALT_LEN:HEADER_LEN]
    ciphertext = data[HEADER_LEN:]

    key = derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("密码错误或文件已损坏")

    _atomic_write(path, plaintext)


# ---------------------------------------------------------------- GUI ----

def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    root = tk.Tk()
    root.title("FileCloak")
    root.geometry("600x400")
    root.resizable(False, False)

    # 强制使用 Windows 原生主题
    style = ttk.Style(root)
    for theme in ("vista", "xpnative", "winnative"):
        if theme in style.theme_names():
            style.theme_use(theme)
            break

    frame = ttk.Frame(root, padding=16)
    frame.pack(fill="both", expand=True)
    frame.columnconfigure(0, weight=1)

    # ---- 文件列表 (ttk.Treeview, 与系统主题一致) ----
    list_frame = ttk.Frame(frame)
    list_frame.grid(row=0, column=0, sticky="ew")
    tree = ttk.Treeview(list_frame, show="tree", selectmode="extended",
                        height=11)
    scroll = ttk.Scrollbar(list_frame, orient="vertical",
                           command=tree.yview)
    tree.config(yscrollcommand=scroll.set)
    tree.pack(side="left", fill="both", expand=True)
    scroll.pack(side="right", fill="y")

    files = []  # 行号 -> 文件路径

    def reload_list():
        """按 files 重建列表显示 (带 🔒 标记)"""
        tree.delete(*tree.get_children())
        for i, p in enumerate(files):
            mark = "🔒 " if is_encrypted(p) else ""
            tree.insert("", "end", iid=str(i), text=mark + p)

    def current_targets():
        """当前操作的行号: 有选中项用选中项, 否则用整个列表"""
        sel = tree.selection()
        return [int(i) for i in sel] if sel else list(range(len(files)))

    def refresh_buttons(*_):
        """按钮状态跟随当前选中(或全部)文件的加密状态:
        都是已加密 -> 加密置灰; 都是未加密 -> 解密置灰"""
        idxs = current_targets()
        if not idxs:
            btn_encrypt.state(["disabled"])
            btn_decrypt.state(["disabled"])
            return
        enc = [is_encrypted(files[i]) for i in idxs]
        btn_encrypt.state(["disabled"] if all(enc) else ["!disabled"])
        btn_decrypt.state(["!disabled"] if any(enc) else ["disabled"])

    tree.bind("<<TreeviewSelect>>", refresh_buttons)

    def add_files():
        for p in filedialog.askopenfilenames():
            if p not in files:
                files.append(p)
        reload_list()
        refresh_buttons()

    def remove_selected():
        for i in sorted(current_targets() if tree.selection() else [],
                        reverse=True):
            del files[i]
        reload_list()
        refresh_buttons()

    def clear_all():
        files.clear()
        reload_list()
        refresh_buttons()

    list_btns = ttk.Frame(frame)
    list_btns.grid(row=1, column=0, sticky="w", pady=(8, 12))
    ttk.Button(list_btns, text="添加",
               command=add_files).pack(side="left", padx=(0, 6))
    ttk.Button(list_btns, text="移除",
               command=remove_selected).pack(side="left", padx=6)
    ttk.Button(list_btns, text="清空",
               command=clear_all).pack(side="left", padx=6)

    # ---- 密码 ----
    pwd_row = ttk.Frame(frame)
    pwd_row.grid(row=2, column=0, sticky="w", pady=(0, 12))
    ttk.Label(pwd_row, text="密码").pack(side="left")
    pwd_var = tk.StringVar()
    pwd_entry = ttk.Entry(pwd_row, textvariable=pwd_var, show="●", width=34)
    pwd_entry.pack(side="left", padx=(8, 6))

    show_var = tk.BooleanVar(value=False)

    def toggle_show():
        pwd_entry.config(show="" if show_var.get() else "●")

    ttk.Checkbutton(pwd_row, text="显示", variable=show_var,
                    command=toggle_show).pack(side="left")

    # ---- 操作按钮 ----
    btns = ttk.Frame(frame)
    btns.grid(row=3, column=0, pady=(2, 10))
    btn_encrypt = ttk.Button(btns, text="加  密", width=12,
                             command=lambda: do_batch(True))
    btn_encrypt.pack(side="left", padx=8)
    btn_decrypt = ttk.Button(btns, text="解  密", width=12,
                             command=lambda: do_batch(False))
    btn_decrypt.pack(side="left", padx=8)
    refresh_buttons()

    # ---- 状态 ----
    status_var = tk.StringVar(value="")
    ttk.Label(frame, textvariable=status_var, foreground="#777777").grid(
        row=4, column=0, sticky="w")

    # ---- 批量操作 ----
    def do_batch(encrypt: bool):
        if not files:
            messagebox.showwarning("FileCloak", "请先添加文件")
            return
        pwd = pwd_var.get()
        if not pwd:
            messagebox.showwarning("FileCloak", "请输入密码")
            return

        root.config(cursor="watch")
        ok, skipped, failed = [], [], []
        targets = current_targets()
        try:
            for n, i in enumerate(targets):
                path = files[i]
                name = os.path.basename(path)
                status_var.set(f"{n + 1}/{len(targets)}  {name}")
                root.update()
                try:
                    if encrypt:
                        if is_encrypted(path):
                            skipped.append((name, "已是加密状态"))
                            continue
                        encrypt_file(path, pwd)
                    else:
                        if not is_encrypted(path):
                            skipped.append((name, "不是加密文件"))
                            continue
                        decrypt_file(path, pwd)
                    ok.append(name)
                except ValueError as e:
                    failed.append((name, str(e)))
                    # 解密时密码错误: 后面的大概率也是同样密码, 直接中止避免无用功
                    if not encrypt and "密码错误" in str(e):
                        for j in targets[n + 1:]:
                            failed.append((os.path.basename(files[j]), "已中止"))
                        break
                except Exception as e:  # noqa: BLE001
                    failed.append((name, f"错误: {e}"))
        finally:
            root.config(cursor="")

        # 更新列表标记与按钮状态
        reload_list()
        refresh_buttons()

        action = "加密" if encrypt else "解密"
        lines = [f"成功 {len(ok)} 个"]
        if skipped:
            lines.append(f"跳过 {len(skipped)} 个 (" +
                         ", ".join(n for n, _ in skipped[:3]) +
                         ("…" if len(skipped) > 3 else "") + ")")
        if failed:
            lines.append("失败 " + str(len(failed)) + " 个:\n" +
                         "\n".join(f"  · {n}: {r}" for n, r in failed[:5]))
        status_var.set("")
        (messagebox.showinfo if not failed else messagebox.showwarning)(
            "FileCloak", "\n".join(lines))

    root.mainloop()


# ---------------------------------------------------------------- CLI ----

def main():
    parser = argparse.ArgumentParser(
        description="FileCloak (支持多文件批量加密/解密)")
    g = parser.add_mutually_exclusive_group()
    g.add_argument("-e", "--encrypt", metavar="文件", nargs="+",
                   help="加密指定文件 (可多个)")
    g.add_argument("-d", "--decrypt", metavar="文件", nargs="+",
                   help="解密指定文件 (可多个)")
    args = parser.parse_args()

    paths = args.encrypt or args.decrypt
    if not paths:
        run_gui()
        return

    encrypting = bool(args.encrypt)
    valid = [p for p in paths if os.path.isfile(p)]
    for p in set(paths) - set(valid):
        print(f"跳过 (文件不存在): {p}")
    if not valid:
        sys.exit("没有可处理的文件")

    pwd = getpass.getpass("请输入密码: ")
    if encrypting:
        if pwd != getpass.getpass("请再次输入密码: "):
            sys.exit("两次输入的密码不一致")

    ok = fail = skip = 0
    for path in valid:
        try:
            if encrypting:
                if is_encrypted(path):
                    print(f"跳过 (已是加密状态): {path}")
                    skip += 1
                    continue
                encrypt_file(path, pwd)
                print(f"加密完成: {path}")
            else:
                if not is_encrypted(path):
                    print(f"跳过 (不是加密文件): {path}")
                    skip += 1
                    continue
                decrypt_file(path, pwd)
                print(f"解密完成: {path}")
            ok += 1
        except ValueError as e:
            print(f"失败: {path} -> {e}")
            fail += 1
            if not encrypting and "密码错误" in str(e):
                print("密码错误, 已中止剩余文件")
                break
        except Exception as e:  # noqa: BLE001
            print(f"失败: {path} -> {e}")
            fail += 1

    print(f"\n合计: 成功 {ok}, 跳过 {skip}, 失败 {fail}")
    if fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
