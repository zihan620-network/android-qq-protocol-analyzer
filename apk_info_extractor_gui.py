import zipfile, os, re, json, sys, struct, threading, traceback
import tkinter as tk
from tkinter import filedialog

FIXED_SIG = "A6B745BF24A2C277527716F6F36EB68D"
FIXED_APP_SIG = "EFBFBDEFBFBD45EFBFBD24EFBFBDEFBFBD7752775C7530303136EFBFBDEFBFBD6EEFBFBDEFBFBD"
FIXED_SUB_APPID_LIST = [1600000226]
FIXED_MAIN_SIG_MAP = 16724722
FIXED_SSO_VERSION = 22
FIXED_QR_V = 5

def uleb128(data, off):
    v = 0; s = 0
    while off < len(data):
        b = data[off]; v |= (b & 0x7F) << s; s += 7; off += 1
        if not (b & 0x80): break
    return v, off

def dex_strings(data):
    if not data or len(data) < 0x70 or data[0:4] != b'dex\n':
        return set()
    off = struct.unpack('<I', data[0x3C:0x40])[0]
    n = struct.unpack('<I', data[0x38:0x3C])[0]
    r = set()
    for i in range(n):
        p = off + i * 4
        if p + 4 > len(data): break
        so = struct.unpack('<I', data[p:p+4])[0]
        if so >= len(data): continue
        ln, dp = uleb128(data, so)
        if dp + ln > len(data): continue
        try:
            s = data[dp:dp+ln].decode('utf-8', errors='ignore')
            if len(s) >= 4: r.add(s)
        except: pass
    return r

def process_apk(path, cb):
    dbg = []
    try:
        z = zipfile.ZipFile(path, 'r')
        try:
            names = [n.filename for n in z.infolist()]
            dbg.append("files: " + str(names))

            # package name
            pkg = "com.tencent.mobileqq"
            try:
                raw = z.read('AndroidManifest.xml')
                if len(raw) >= 8 and struct.unpack('<I', raw[0:4])[0] == 0x00080003:
                    so = struct.unpack('<I', raw[4:8])[0]
                    if so + 8 <= len(raw):
                        sc = struct.unpack('<I', raw[so:so+4])[0]
                        ss = struct.unpack('<I', raw[so+4:so+8])[0]
                        st = so + ss
                        for i in range(sc):
                            if st + 2 > len(raw): break
                            sl = struct.unpack('<H', raw[st:st+2])[0]
                            if sl == 0: st += 2; continue
                            if st + 2 + sl * 2 > len(raw): break
                            s = raw[st+2:st+2+sl*2].decode('utf-16le', errors='ignore').rstrip('\0')
                            if re.match(r'^[a-zA-Z][\w.]*\.[\w.]+$', s): pkg = s; break
                            st += 2 + sl * 2 + 2
            except: pass

            # revision.txt
            rev = None
            for n in names:
                if n.lower().endswith('revision.txt'):
                    rev = z.read(n).decode('utf-8', errors='ignore').strip()
                    dbg.append("rev file: " + n)
                    break
            dbg.append("rev raw: " + repr(rev))

            # appid.ini
            aid = None
            for n in names:
                if n.lower().endswith('appid.ini'):
                    aid = z.read(n).decode('utf-8', errors='ignore').strip()
                    dbg.append("aid file: " + n)
                    break
            dbg.append("aid raw: " + repr(aid))

            # parse revision.txt (key=value + raw lines)
            rdata = {}
            raw_lines = []
            if rev:
                for line in rev.split('\n'):
                    line = line.strip()
                    raw_lines.append(line)
                    if '=' in line:
                        k, v = line.split('=', 1)
                        rdata[k.strip()] = v.strip().strip('"')
            dbg.append("rdata: " + str(rdata))
            dbg.append("raw_lines: " + str(raw_lines))

            # version from revision.txt
            ver = rdata.get('ver', '') or rdata.get('Version', '') or rdata.get('VER', '')
            if not ver and rev:
                for line in raw_lines:
                    m = re.match(r'^V?(\d+\.\d+\.\d+(?:\.\d+)?)', line)
                    if m:
                        ver = ('V' + m.group(1)) if not line.startswith('V') else line
                        break
            dbg.append("ver: " + repr(ver))

            ver_clean = ver.lstrip('V') if ver else ''
            parts = ver_clean.split('.')
            apk_v = '.'.join(parts[:3]) if len(parts) >= 3 else ''
            apk_v_1 = '.'.join(parts[:4]) if len(parts) >= 4 else ''
            dbg.append("apk_v: " + repr(apk_v))

            # parse appid.ini
            appids = []
            if aid:
                for line in aid.split('\n'):
                    for m in re.finditer(r'"appId"\s*:\s*"(\d+)"', line):
                        appids.append(int(m.group(1)))
                    for m in re.finditer(r'(\d{9})', line):
                        if m.group(1) not in [str(a) for a in appids]:
                            appids.append(int(m.group(1)))
            dbg.append("appids: " + str(appids))

            # dex files
            dex_names = [n for n in names if n.endswith('.dex')]
            dbg.append("dex: " + str(dex_names))
            all_strs = set()
            for dn in dex_names:
                all_strs.update(dex_strings(z.read(dn)))
            dbg.append("dex_strings_count: " + str(len(all_strs)))
            # log some sample strings
            dbg.append("dex_sample: " + str(sorted(list(all_strs))[:50]))

            # sdk version: ONLY from dex, search 6.0.0.xxxx (4 digits)
            sdk_ver = rdata.get('sdkVer', '') or rdata.get('SdkVersion', '') or rdata.get('SDKVer', '')
            if not sdk_ver:
                candidates = [s for s in all_strs if re.match(r'^6\.0\.0\.\d{4}$', s)]
                dbg.append("sdk_candidates: " + str(candidates))
                if candidates:
                    sdk_ver = max(candidates, key=lambda x: int(x.rsplit('.',1)[-1]))
            dbg.append("sdk_ver: " + repr(sdk_ver))

            # apk_v_1 from dex: search for "apk_v." pattern
            if not apk_v_1 and apk_v:
                prefix = apk_v + '.'
                for s in all_strs:
                    if s.startswith(prefix) and re.match(r'^\d+\.\d+\.\d+\.\d+$', s):
                        apk_v_1 = s
                        break
            dbg.append("apk_v_1: " + repr(apk_v_1))

            # internal ver: 1) revision.txt key 2) raw line matching A{x.x.x}.{hash}
            internal_ver = rdata.get('internalVer', '') or rdata.get('InternalVer', '')
            if not internal_ver and rev:
                for line in raw_lines:
                    m = re.match(r'^A?\d+\.\d+\.\d+\.[a-f0-9]{8}$', line)
                    if m:
                        internal_ver = line
                        break
            dbg.append("internal_ver_raw: " + repr(internal_ver))
            if internal_ver:
                if not internal_ver.startswith('A'):
                    internal_ver = 'A' + internal_ver
            elif apk_v:
                bad_hashes = {'00000000','ffff0000','ffffffff','0000ffff','00ff00ff','ff00ff00'}
                hashes = [s for s in all_strs if re.match(r'^[a-f0-9]{8}$', s)
                          and any(c in 'abcdef' for c in s)
                          and s not in bad_hashes
                          and s != '00000000']
                dbg.append("hash_candidates: " + str(hashes))
                h = hashes[0] if hashes else '00000000'
                internal_ver = f"A{apk_v}.{h}"
            dbg.append("internal_ver: " + repr(internal_ver))

            # build time
            bt = None
            for s in all_strs:
                m = re.match(r'^1[5-7]\d{8}$', s)
                if m: bt = int(s); break
            if not bt and rdata.get('buildTime'):
                try: bt = int(rdata['buildTime'])
                except: pass

            # mMiscBitmap
            mmb = None
            for s in all_strs:
                if 'mMiscBitmap' in s:
                    m = re.search(r'(\d{6,10})', s)
                    if m:
                        try: mmb = int(m.group(1)); break
                        except: pass
            if not mmb: mmb = 150470524

            appid = appids[0] if len(appids) >= 1 else 0
            appid2 = appids[1] if len(appids) >= 2 else appid

            result = {
                "ApkId": pkg, "Apk_Sig": FIXED_SIG, "App_Sig": FIXED_APP_SIG,
                "Apk_v": apk_v, "Apk_v_1": apk_v_1,
                "Ver": internal_ver or "",
                "Appid": appid, "Appid2": appid2, "BuildTime": bt or 0,
                "SdkVersion": sdk_ver or "", "mMiscBitmap": mmb,
                "_sub_appid_list": FIXED_SUB_APPID_LIST, "_main_sig_map": FIXED_MAIN_SIG_MAP,
                "SSOVersion": FIXED_SSO_VERSION, "qr_v": FIXED_QR_V
            }

            cb(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=False), None, dbg)
        finally:
            z.close()
    except Exception as e:
        cb(None, str(e) + "\n" + traceback.format_exc(), dbg)


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Android QQ 协议自分析工具   By.JackHan")
        self.root.geometry("450x300")
        self.root.minsize(400, 360)
        self.root.configure(bg="#f5f6fa")

        # set application icon (bundled via --add-data, loaded from _MEIPASS)
        icon_path = None
        base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
        for cand in [os.path.join(base, 'icon.ico'), os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon.ico')]:
            if os.path.exists(cand):
                icon_path = cand
                break
        try:
            if icon_path:
                self.root.iconbitmap(icon_path)
        except:
            pass

        self.last_json = ""
        self.btns = {}
        self._ui()

    def _ui(self):
        # ── top accent bar ──
        accent = tk.Frame(self.root, bg="#2f5dcf", height=5)
        accent.pack(fill=tk.X)

        # ── header ──
        header = tk.Frame(self.root, bg="#2f5dcf", height=56)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        title_text = "Android QQ 协议自分析工具   By.JackHan"
        tk.Label(header, text=title_text, fg="white", bg="#2f5dcf",
                 font=("Microsoft YaHei UI", 14, "bold")).pack(side=tk.LEFT, padx=18, pady=14)

        # ── toolbar ──
        bar = tk.Frame(self.root, bg="#f5f6fa")
        bar.pack(fill=tk.X, pady=(10, 8), padx=16)

        def btn(parent, text, color, hover, cmd, **kw):
            b = tk.Button(parent, text=text, command=cmd, font=("Microsoft YaHei UI", 9),
                          bg=color, fg="white", padx=14, pady=5, cursor="hand2",
                          relief="flat", bd=0, activebackground=hover,
                          highlightthickness=0, **kw)
            b.pack(side=tk.LEFT, padx=(0, 10))

            def on_enter(e):
                b.configure(bg=hover)
                b.configure(cursor="hand2")
            def on_leave(e):
                b.configure(bg=color)
            b.bind("<Enter>", on_enter)
            b.bind("<Leave>", on_leave)
            return b

        self.sb = btn(bar, " 选择 APK ", "#22c55e", "#16a34a", self.sel)
        self.cb = btn(bar, " 复制 JSON ", "#3b82f6", "#2563eb", self.cp, state=tk.DISABLED)
        self.clb = btn(bar, " 清空 ", "#ef4444", "#dc2626", self.clr)

        # ── status bar ──
        self.st = tk.Label(self.root, text="就绪，请选择 APK 文件", fg="#64748b", bg="#f5f6fa",
                           font=("Microsoft YaHei UI", 9), anchor=tk.W)
        self.st.pack(fill=tk.X, padx=16, pady=(0, 6))

        # ── output area ──
        frm = tk.Frame(self.root, bg="white", bd=1, relief=tk.SOLID, highlightbackground="#e2e8f0")
        frm.pack(fill=tk.BOTH, expand=True, padx=16, pady=(0, 16))

        self.tx = tk.Text(frm, font=("Consolas", 10), wrap=tk.NONE,
                          bg="white", fg="#1e293b", insertbackground="#1e293b",
                          relief="flat", bd=0, padx=10, pady=10)
        self.tx.pack(fill=tk.BOTH, expand=True, side=tk.LEFT)

        vs = tk.Scrollbar(frm, orient=tk.VERTICAL, command=self.tx.yview, relief=tk.FLAT)
        hs = tk.Scrollbar(self.root, orient=tk.HORIZONTAL, command=self.tx.xview, relief=tk.FLAT)
        self.tx.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        hs.pack(fill=tk.X, padx=16, before=frm)

        self.tx.tag_config("green", foreground="#15803d")
        self.tx.tag_config("red", foreground="#dc2626")
        self.tx.tag_config("key", foreground="#7c3aed")
        self.tx.tag_config("str", foreground="#0369a1")
        self.tx.tag_config("num", foreground="#c2410c")
        self.tx.tag_config("dim", foreground="#94a3b8")

        self.tx.insert(tk.END, "点击 \"选择 APK\" 或拖入文件开始分析\n", "dim")

    def sel(self):
        fp = filedialog.askopenfilename(title="选择 APK", filetypes=[("APK", "*.apk"), ("All", "*.*")])
        if fp: self.start(fp)

    def start(self, path):
        self.st.configure(text="解析中: " + os.path.basename(path), fg="#c2410c")
        self.tx.delete(1.0, tk.END)
        self.tx.insert(tk.END, "正在解析，请稍候...\n")
        self.cb.configure(state=tk.DISABLED)
        self.root.update()
        t = threading.Thread(target=process_apk, args=(path, self.done))
        t.daemon = True; t.start()

    def done(self, js, err, dbg):
        self.root.after(0, self.upd, js, err, dbg)

    def upd(self, js, err, dbg):
        self.tx.delete(1.0, tk.END)
        if err:
            self.tx.insert(tk.END, "错误:\n", "red")
            self.tx.insert(tk.END, err + "\n")
            self._dbg(dbg)
            self.st.configure(text="解析失败", fg="#dc2626")
        else:
            try:
                data = json.loads(js)
                for k, v in data.items():
                    self.tx.insert(tk.END, '"', "key")
                    self.tx.insert(tk.END, k, "key")
                    self.tx.insert(tk.END, '": ', "key")
                    if isinstance(v, str):
                        self.tx.insert(tk.END, '"', "str")
                        self.tx.insert(tk.END, v, "str")
                        self.tx.insert(tk.END, '"', "str")
                    elif isinstance(v, (int, float)):
                        self.tx.insert(tk.END, str(v), "num")
                    elif isinstance(v, list):
                        self.tx.insert(tk.END, json.dumps(v), "str")
                    else:
                        self.tx.insert(tk.END, json.dumps(v), "str")
                    self.tx.insert(tk.END, ",\n", "dim")
                self.tx.delete("end-2c", "end-1c")
            except:
                self.tx.insert(tk.END, js)
            self.last_json = js
            self.st.configure(text="解析完成", fg="#15803d")
            self.cb.configure(state=tk.NORMAL)
            self._dbg(dbg)

    def _dbg(self, dbg):
        if dbg:
            self.tx.insert(tk.END, "\n\n───── 调试信息 ─────\n", "dim")
            for d in dbg:
                self.tx.insert(tk.END, d + "\n", "dim")

    def cp(self):
        if self.last_json:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.last_json)
            self.st.configure(text="已复制到剪贴板", fg="#15803d")

    def clr(self):
        self.tx.delete(1.0, tk.END)
        self.last_json = ""
        self.cb.configure(state=tk.DISABLED)
        self.st.configure(text="已清空", fg="#64748b")
        self.tx.insert(tk.END, "点击 \"选择 APK\" 或拖入文件开始分析\n", "dim")


if __name__ == '__main__':
    try:
        root = tk.Tk()
        App(root)
        root.mainloop()
    except Exception as e:
        import ctypes
        ctypes.windll.user32.MessageBoxW(0, str(e) + "\n\n" + traceback.format_exc(), "Error", 0)