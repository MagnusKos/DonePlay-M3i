"""GUI firmware image browser/editor."""
import os
import struct
import subprocess
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image, ImageTk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', '..'))
from rk260x.imgmap import load_map, save_map, rows_of, map_from_rows

FW_DEFAULT = os.environ.get('RK260X_FW') or os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'firmwares', 'Firmware M3i 070930.rfw')
MAP_DEFAULT = os.environ.get('RK260X_MAP') or os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'data', 'captures', 'm3i.json')


class FWImage:
    @staticmethod
    def decode(data, w, h):
        n = min(len(data) // 2, w * h)
        px = [(data[2*i] << 8) | data[2*i+1] for i in range(n)]
        buf = bytearray()
        for p in px:
            buf += bytes([((p >> 11) & 0x1F) << 3, ((p >> 5) & 0x3F) << 2, (p & 0x1F) << 3])
        return Image.frombytes('RGB', (w, h), bytes(buf))

    @staticmethod
    def encode(img):
        img = img.convert('RGB')
        buf = bytearray()
        for r, g, b in img.getdata():
            p = ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)
            buf += bytes([(p >> 8) & 0xFF, p & 0xFF])
        return bytes(buf)


class App:
    def __init__(self, root):
        self.root = root
        root.title('M3i firmware image editor')
        self.fw = bytearray()
        self.entries = []
        self.map_path = MAP_DEFAULT
        self.map = None
        self.modified = set()
        self.filter_text = ''
        self.view = {'off': 0, 'w': 220, 'h': 176}   # custom view state
        self.build_files()

    # ------------------------------------------------------------------ UI
    def build_files(self):
        for w in self.root.winfo_children():
            w.destroy()
        # toolbar
        top = tk.Frame(self.root); top.pack(fill=tk.X, padx=4, pady=2)
        tk.Button(top, text='Open firmware', command=self.open_fw).pack(side=tk.LEFT)
        tk.Button(top, text='Open map', command=self.open_tl).pack(side=tk.LEFT)
        tk.Button(top, text='Save firmware as...', command=self.save_fw).pack(side=tk.LEFT, padx=(16, 0))
        tk.Button(top, text='Export PNG', command=self.export_png).pack(side=tk.LEFT)
        tk.Button(top, text='Import PNG', command=self.import_png).pack(side=tk.LEFT)
        # search
        srow = tk.Frame(self.root); srow.pack(fill=tk.X, padx=4, pady=2)
        tk.Label(srow, text='Search:').pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace_add('write', lambda *_: self.refresh())
        tk.Entry(srow, textvariable=self.search_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        # custom view controls
        crow = tk.Frame(self.root); crow.pack(fill=tk.X, padx=4, pady=2)
        tk.Label(crow, text='Offset:').pack(side=tk.LEFT)
        self.off_var = tk.StringVar(value='0')
        tk.Entry(crow, textvariable=self.off_var, width=12).pack(side=tk.LEFT)
        tk.Label(crow, text='W:').pack(side=tk.LEFT)
        self.w_var = tk.StringVar(value='220')
        tk.Entry(crow, textvariable=self.w_var, width=5).pack(side=tk.LEFT)
        tk.Label(crow, text='H:').pack(side=tk.LEFT)
        self.h_var = tk.StringVar(value='176')
        tk.Entry(crow, textvariable=self.h_var, width=5).pack(side=tk.LEFT)
        tk.Button(crow, text='View', command=self.view_custom).pack(side=tk.LEFT)
        tk.Button(crow, text='< prev chunk', command=lambda: self.step_chunk(-1)).pack(side=tk.LEFT, padx=(16, 0))
        tk.Button(crow, text='next chunk >', command=lambda: self.step_chunk(1)).pack(side=tk.LEFT)
        tk.Button(crow, text='Add view to map', command=self.add_to_map).pack(side=tk.LEFT, padx=(16, 0))
        tk.Button(crow, text='Remove entry', command=self.remove_entry).pack(side=tk.LEFT)
        tk.Button(crow, text='Save map (JSON)', command=self.save_tl).pack(side=tk.LEFT)
        # main area
        main = tk.Frame(self.root); main.pack(fill=tk.BOTH, expand=True)
        sb = tk.Scrollbar(main)
        self.listbox = tk.Listbox(main, width=36, yscrollcommand=sb.set)
        sb.config(command=self.listbox.yview)
        sb.pack(side=tk.RIGHT, fill=tk.Y)
        self.listbox.pack(side=tk.LEFT, fill=tk.Y)
        self.listbox.bind('<<ListboxSelect>>', lambda e: self.on_select())
        self.canvas = tk.Label(main, text='preview')
        self.canvas.pack(side=tk.RIGHT, expand=True, padx=8)
        # tools row
        trow = tk.Frame(self.root); trow.pack(fill=tk.X, padx=4, pady=2)
        tk.Label(trow, text='Tools:').pack(side=tk.LEFT)
        tk.Button(trow, text='Build flash stream', command=self.tool_build).pack(side=tk.LEFT)
        tk.Button(trow, text='Flash (device in PLAY-boot mode!)', command=self.tool_flash).pack(side=tk.LEFT)
        tk.Button(trow, text='Firmware info (rfw.py)', command=self.tool_info).pack(side=tk.LEFT)
        self.status = tk.Label(self.root, text='open firmware + map', fg='blue', anchor='w')
        self.status.pack(fill=tk.X)
        # defaults
        if os.path.exists(FW_DEFAULT) and not self.fw:
            self.fw = bytearray(open(FW_DEFAULT, 'rb').read())
        if os.path.exists(self.map_path):
            self.map = load_map(self.map_path)
            self.entries = rows_of(self.map)
        self.refresh()

    # ------------------------------------------------------------- helpers
    def shown_entries(self):
        if not self.filter_text:
            return self.entries
        f = self.filter_text.lower()
        return [e for e in self.entries if f in e[0].lower()]

    def refresh(self):
        self.filter_text = self.search_var.get() if hasattr(self, 'search_var') else ''
        self.listbox.delete(0, tk.END)
        for name, off, w, h in self.shown_entries():
            mark = '*' if (name, off) in self.modified else ' '
            self.listbox.insert(tk.END, f'{mark} {name} {w}x{h} @{off:#x}')
        self.update_status()

    def cur(self):
        sel = self.listbox.curselection()
        shown = self.shown_entries()
        if not sel or sel[0] >= len(shown):
            return None
        return shown[sel[0]]

    def show_image(self, off, w, h, label=''):
        if not self.fw:
            return
        if off < 0 or off + w * h * 2 > len(self.fw):
            messagebox.showwarning('range', 'offset out of firmware range')
            return
        img = FWImage.decode(self.fw[off:off + w * h * 2], w, h)
        self.preview = ImageTk.PhotoImage(img)
        self.canvas.config(image=self.preview)
        self.update_status(f'{label} {w}x{h} @{off:#x}' if label else f'view {w}x{h} @{off:#x}')

    def on_select(self):
        e = self.cur()
        if e:
            self.show_image(e[1], e[2], e[3], e[0])

    def update_status(self, msg=None):
        if msg is None:
            msg = f'fw: {len(self.fw)}B  map: {len(self.entries)}  modified: {len(self.modified)}'
        self.status.config(text=msg)

    # ------------------------------------------------------------- actions
    def open_fw(self):
        p = filedialog.askopenfilename(title='firmware')
        if p:
            self.fw = bytearray(open(p, 'rb').read())
            self.update_status()

    def open_tl(self):
        p = filedialog.askopenfilename(title='map', filetypes=[('map', '*.json'), ('all', '*')])
        if p:
            self.map_path = p
            self.map = load_map(p)
            self.entries = rows_of(self.map)
            self.refresh()

    def view_custom(self):
        try:
            self.view = {'off': int(self.off_var.get(), 0), 'w': int(self.w_var.get()), 'h': int(self.h_var.get())}
        except ValueError:
            messagebox.showerror('input', 'bad offset/w/h')
            return
        self.show_image(**self.view)

    def step_chunk(self, direction):
        try:
            off = int(self.off_var.get(), 0)
            w, h = int(self.w_var.get()), int(self.h_var.get())
        except ValueError:
            return
        off = max(0, off + direction * w * h * 2)
        self.off_var.set(str(off))
        self.view = {'off': off, 'w': w, 'h': h}
        self.show_image(off, w, h)

    def add_to_map(self):
        try:
            off, w, h = int(self.off_var.get(), 0), int(self.w_var.get()), int(self.h_var.get())
        except ValueError:
            return
        name = simpledialog.askstring('name', 'entry name:', parent=self.root)
        if not name:
            return
        self.entries.append([name, off, w, h])
        self.entries.sort(key=lambda e: e[1])
        self.refresh()
        self.update_status(f'added {name} @{off:#x} (unsaved map changes)')

    def remove_entry(self):
        e = self.cur()
        if not e:
            return
        self.entries = [x for x in self.entries if x is not e]
        self.refresh()

    def save_tl(self):
        p = filedialog.asksaveasfilename(defaultextension='.json', initialfile='m3i_full.json')
        if not p:
            return
        save_map(p, map_from_rows(self.entries, self.map),
                 device=(self.map or {}).get('device'),
                 firmware=(self.map or {}).get('firmware'))
        self.map_path = p
        self.update_status(f'map saved: {p}')

    def export_png(self):
        e = self.cur()
        if e and self.fw:
            name, off, w, h = e
            p = filedialog.asksaveasfilename(defaultextension='.png', initialfile=f'{name}.png')
            if p:
                FWImage.decode(self.fw[off:off + w * h * 2], w, h).save(p)
                self.update_status(f'exported {p}')
        else:
            # export current custom view
            try:
                off, w, h = int(self.off_var.get(), 0), int(self.w_var.get()), int(self.h_var.get())
                p = filedialog.asksaveasfilename(defaultextension='.png', initialfile=f'view_{off:#x}.png')
                if p:
                    FWImage.decode(self.fw[off:off + w * h * 2], w, h).save(p)
            except (ValueError, TypeError):
                messagebox.showerror('export', 'select an entry or set a valid view')

    def import_png(self):
        e = self.cur()
        if not e or not self.fw:
            messagebox.showinfo('import', 'select a mapped entry first')
            return
        name, off, w, h = e
        p = filedialog.askopenfilename(filetypes=[('PNG', '*.png')])
        if not p:
            return
        img = Image.open(p).convert('RGB').resize((w, h))
        data = FWImage.encode(img)
        self.fw[off:off + len(data)] = data
        self.modified.add((name, off))
        self.refresh()
        self.on_select()
        self.update_status(f'IMPORTED {name} — save firmware when done')

    def save_fw(self):
        p = filedialog.asksaveasfilename(defaultextension='.rfw', initialfile='modified.rfw')
        if not p:
            return
        open(p, 'wb').write(bytes(self.fw))
        self.update_status(f'saved {p}')

    # --------------------------------------------------------------- tools
    def tool_build(self):
        fw = filedialog.askopenfilename(title='firmware to build from (usually your saved modified.rfw)')
        if not fw:
            return
        out = os.path.join(HERE, 'built_stream.json')
        from ..cli import main as rkx_main
        import io, contextlib
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                rkx_main(['build', fw, out])
            r = type('R', (), {'stdout': buf.getvalue(), 'stderr': ''})()
        except SystemExit as e:
            r = type('R', (), {'stdout': buf.getvalue(), 'stderr': 'exit %s' % e.code})()
        self.update_status('build: ' + (r.stdout + r.stderr).strip().replace('\n', ' | ')[:200])

    def tool_flash(self):
        if not messagebox.askyesno('flash', 'Player in PLAY-boot mode?\nThis writes flash!'):
            return
        from ..cli import main as rkx_main
        import io, contextlib
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
                rkx_main(['flash'])
            r = type('R', (), {'stdout': buf.getvalue(), 'stderr': ''})()
        except SystemExit as e:
            r = type('R', (), {'stdout': buf.getvalue(), 'stderr': 'exit %s' % e.code})()
        self.update_status('flash: ' + (r.stdout + r.stderr).strip().replace('\n', ' | ')[:200])

    def tool_info(self):
        fw = filedialog.askopenfilename(title='firmware for info')
        if not fw:
            return
        from ..cli import main as rkx_main
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            rkx_main(['rfw-info', fw])
        r = type('R', (), {'stdout': buf.getvalue(), 'stderr': ''})()
        win = tk.Toplevel(self.root)
        tk.Text(win, height=24, width=80).pack()
        t = win.winfo_children()[0]
        t.insert('1.0', r.stdout + r.stderr)




def run(map_path=None, firmware_path=None):
    global TL_DEFAULT, FW_DEFAULT
    if map_path:
        global MAP_DEFAULT
        MAP_DEFAULT = map_path
    if firmware_path:
        FW_DEFAULT = firmware_path
    root = tk.Tk()
    App(root)
    root.mainloop()
