# -*- coding: utf-8 -*-
"""
FileCloak (English UI) — file weighting tool (Windows)

Same core as filecloak.py, with an all-English, neutral-worded interface:
  - "Weight" / "Unweight" instead of encrypt/decrypt wording
  - "Key" instead of password
  - Fully compatible: files processed by either version interoperate

Crypto design (unchanged):
  - AES-256-GCM, key derived via PBKDF2-HMAC-SHA256 (600,000 iterations)
  - In-place: filename/extension untouched, content becomes random bytes
  - File layout: [4B magic "FLE1"][16B salt][12B nonce][ciphertext+tag]

Usage:
  python filecloak_en.py                  -> GUI
  python filecloak_en.py -w file1 file2   -> weight files
  python filecloak_en.py -u file1 file2   -> unweight files
"""

import os
import sys
import argparse
import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

MAGIC = b"FLE1"          # identical format to filecloak.py
SALT_LEN = 16
NONCE_LEN = 12
KDF_ITERATIONS = 600_000
HEADER_LEN = len(MAGIC) + SALT_LEN + NONCE_LEN


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def is_weighted(path: str) -> bool:
    """Whether the file has already been weighted."""
    try:
        with open(path, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC
    except OSError:
        return False


def _atomic_write(path: str, data: bytes):
    tmp = path + ".tmp_fle"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def weight_file(path: str, password: str):
    if is_weighted(path):
        raise ValueError("File is already weighted")
    with open(path, "rb") as f:
        plaintext = f.read()
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    _atomic_write(path, MAGIC + salt + nonce + ciphertext)


def unweight_file(path: str, password: str):
    with open(path, "rb") as f:
        data = f.read()
    if data[:len(MAGIC)] != MAGIC:
        raise ValueError("Not a weighted file")
    salt = data[4:4 + SALT_LEN]
    nonce = data[4 + SALT_LEN:HEADER_LEN]
    ciphertext = data[HEADER_LEN:]
    key = derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        raise ValueError("Wrong key or damaged file")
    _atomic_write(path, plaintext)


# ---------------------------------------------------------------- GUI ----

def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    root = tk.Tk()
    root.title("FileCloak")
    root.geometry("600x400")
    root.resizable(False, False)

    style = ttk.Style(root)
    for theme in ("vista", "xpnative", "winnative"):
        if theme in style.theme_names():
            style.theme_use(theme)
            break

    frame = ttk.Frame(root, padding=16)
    frame.pack(fill="both", expand=True)
    frame.columnconfigure(0, weight=1)

    # ---- file list (ttk.Treeview, matches native theme) ----
    list_frame = ttk.Frame(frame)
    list_frame.grid(row=0, column=0, sticky="ew")
    tree = ttk.Treeview(list_frame, show="tree", selectmode="extended",
                        height=11)
    scroll = ttk.Scrollbar(list_frame, orient="vertical",
                           command=tree.yview)
    tree.config(yscrollcommand=scroll.set)
    tree.pack(side="left", fill="both", expand=True)
    scroll.pack(side="right", fill="y")

    files = []  # row index -> path

    def reload_list():
        tree.delete(*tree.get_children())
        for i, p in enumerate(files):
            mark = "[W] " if is_weighted(p) else ""
            tree.insert("", "end", iid=str(i), text=mark + p)

    def current_targets():
        """Selected rows, or the whole list when nothing is selected."""
        sel = tree.selection()
        return [int(i) for i in sel] if sel else list(range(len(files)))

    def refresh_buttons(*_):
        """Buttons follow the state of the selected (or all) files:
        all weighted -> Weight disabled; none weighted -> Unweight disabled"""
        idxs = current_targets()
        if not idxs:
            btn_weight.state(["disabled"])
            btn_unweight.state(["disabled"])
            return
        w = [is_weighted(files[i]) for i in idxs]
        btn_weight.state(["disabled"] if all(w) else ["!disabled"])
        btn_unweight.state(["!disabled"] if any(w) else ["disabled"])

    tree.bind("<<TreeviewSelect>>", refresh_buttons)

    def add_files():
        for p in filedialog.askopenfilenames():
            if p not in files:
                files.append(p)
        reload_list()
        refresh_buttons()

    def remove_selected():
        if tree.selection():
            for i in sorted((int(x) for x in tree.selection()),
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
    ttk.Button(list_btns, text="Add",
               command=add_files).pack(side="left", padx=(0, 6))
    ttk.Button(list_btns, text="Remove",
               command=remove_selected).pack(side="left", padx=6)
    ttk.Button(list_btns, text="Clear",
               command=clear_all).pack(side="left", padx=6)

    # ---- key ----
    key_row = ttk.Frame(frame)
    key_row.grid(row=2, column=0, sticky="w", pady=(0, 12))
    ttk.Label(key_row, text="Key").pack(side="left")
    key_var = tk.StringVar()
    key_entry = ttk.Entry(key_row, textvariable=key_var, show="●", width=34)
    key_entry.pack(side="left", padx=(8, 6))

    show_var = tk.BooleanVar(value=False)

    def toggle_show():
        key_entry.config(show="" if show_var.get() else "●")

    ttk.Checkbutton(key_row, text="Show", variable=show_var,
                    command=toggle_show).pack(side="left")

    # ---- action buttons ----
    btns = ttk.Frame(frame)
    btns.grid(row=3, column=0, pady=(2, 10))
    btn_weight = ttk.Button(btns, text="Weight", width=12,
                            command=lambda: do_batch(True))
    btn_weight.pack(side="left", padx=8)
    btn_unweight = ttk.Button(btns, text="Unweight", width=12,
                              command=lambda: do_batch(False))
    btn_unweight.pack(side="left", padx=8)
    refresh_buttons()

    # ---- status ----
    status_var = tk.StringVar(value="")
    ttk.Label(frame, textvariable=status_var, foreground="#777777").grid(
        row=4, column=0, sticky="w")

    # ---- batch ----
    def do_batch(weighting: bool):
        if not files:
            messagebox.showwarning("FileCloak", "Add files first")
            return
        key = key_var.get()
        if not key:
            messagebox.showwarning("FileCloak", "Enter a key")
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
                    if weighting:
                        if is_weighted(path):
                            skipped.append((name, "already weighted"))
                            continue
                        weight_file(path, key)
                    else:
                        if not is_weighted(path):
                            skipped.append((name, "not weighted"))
                            continue
                        unweight_file(path, key)
                    ok.append(name)
                except ValueError as e:
                    failed.append((name, str(e)))
                    # wrong key: the rest will fail the same way, stop early
                    if not weighting and "Wrong key" in str(e):
                        for j in targets[n + 1:]:
                            failed.append((os.path.basename(files[j]),
                                           "aborted"))
                        break
                except Exception as e:  # noqa: BLE001
                    failed.append((name, f"error: {e}"))
        finally:
            root.config(cursor="")

        reload_list()
        refresh_buttons()

        lines = [f"Done: {len(ok)}"]
        if skipped:
            lines.append(f"Skipped: {len(skipped)} (" +
                         ", ".join(n for n, _ in skipped[:3]) +
                         ("…" if len(skipped) > 3 else "") + ")")
        if failed:
            lines.append(f"Failed: {len(failed)}\n" +
                         "\n".join(f"  · {n}: {r}" for n, r in failed[:5]))
        status_var.set("")
        (messagebox.showinfo if not failed else messagebox.showwarning)(
            "FileCloak", "\n".join(lines))

    root.mainloop()


# ---------------------------------------------------------------- CLI ----

def main():
    parser = argparse.ArgumentParser(description="FileCloak")
    g = parser.add_mutually_exclusive_group()
    g.add_argument("-w", "--weight", metavar="FILE", nargs="+",
                   help="weight files")
    g.add_argument("-u", "--unweight", metavar="FILE", nargs="+",
                   help="unweight files")
    args = parser.parse_args()

    paths = args.weight or args.unweight
    if not paths:
        run_gui()
        return

    weighting = bool(args.weight)
    valid = [p for p in paths if os.path.isfile(p)]
    for p in set(paths) - set(valid):
        print(f"skipped (not found): {p}")
    if not valid:
        sys.exit("no files to process")

    key = getpass.getpass("Key: ")
    if weighting:
        if key != getpass.getpass("Confirm key: "):
            sys.exit("keys do not match")

    ok = fail = skip = 0
    for path in valid:
        try:
            if weighting:
                if is_weighted(path):
                    print(f"skipped (already weighted): {path}")
                    skip += 1
                    continue
                weight_file(path, key)
                print(f"weighted: {path}")
            else:
                if not is_weighted(path):
                    print(f"skipped (not weighted): {path}")
                    skip += 1
                    continue
                unweight_file(path, key)
                print(f"unweighted: {path}")
            ok += 1
        except ValueError as e:
            print(f"failed: {path} -> {e}")
            fail += 1
            if not weighting and "Wrong key" in str(e):
                print("wrong key, aborted remaining files")
                break
        except Exception as e:  # noqa: BLE001
            print(f"failed: {path} -> {e}")
            fail += 1

    print(f"\ntotal: {ok} done, {skip} skipped, {fail} failed")
    if fail:
        sys.exit(1)


if __name__ == "__main__":
    main()
