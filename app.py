"""
ScanShield Desktop - تطبيق فحص أمان المواقع، يشتغل بالكامل من جهازك.
بدون سيرفر، بدون اتصال بأي خدمة مركزية - الفحص يصير مباشرة من جهازك
لجهاز الموقع المستهدف.
"""
import os
import sys
import threading
import queue
import datetime
import subprocess
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox

from core import verification, blocklist, local_log, config, geo_check, scoring, report_export
from core.scanners import ALL_SCANNERS


def resource_path(relative_path: str) -> str:
    """يرجع المسار الصحيح للملفات المرفقة (زي الأيقونة)، سواء وقت
    التطوير العادي أو بعد التجميع كملف exe واحد عبر PyInstaller."""
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)

FONT_NORMAL = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 11, "bold")
FONT_TITLE = ("Segoe UI", 16, "bold")
BG = "#0E1E1C"
SURFACE = "#15302B"
TEXT = "#EAF3EF"
MUTED = "#8FACA3"
ACCENT = "#E8B33D"
SUCCESS = "#52B788"
DANGER = "#E2634F"


class ScanShieldApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{config.APP_NAME} - فحص أمان المواقع")
        self.geometry("560x680")
        self.configure(bg=BG)
        self.resizable(False, False)
        try:
            self.iconbitmap(resource_path("icon.ico"))
        except Exception:
            pass  # تجاهل لو الأيقونة مو موجودة (مثلاً وقت التطوير على لينكس)

        self.state = {"domain": None, "method": None, "token": None}
        self.result_queue = queue.Queue()

        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True, padx=20, pady=20)

        self._build_header(container)

        self.frames = {}
        body = tk.Frame(container, bg=BG)
        body.pack(fill="both", expand=True, pady=(16, 0))
        self.body = body

        for F in (GeoCheckFrame, BlockedFrame, DomainFrame, VerifyFrame, ConsentFrame, ResultsFrame):
            frame = F(body, self)
            self.frames[F] = frame
            frame.place(relx=0, rely=0, relwidth=1, relheight=1)

        self.show_frame(GeoCheckFrame)

    def _build_header(self, parent):
        header = tk.Frame(parent, bg=BG)
        header.pack(fill="x")
        tk.Label(header, text=f"◆ {config.APP_NAME}", font=FONT_TITLE, bg=BG, fg=TEXT).pack()
        tk.Label(header, text="افحص موقعك بنفسك. لا أحد غيرك.", font=FONT_NORMAL, bg=BG, fg=MUTED).pack()

    def show_frame(self, frame_class):
        frame = self.frames[frame_class]
        frame.tkraise()
        if hasattr(frame, "on_show"):
            frame.on_show()


class StyledFrame(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent, bg=SURFACE, highlightbackground="#2A4A42", highlightthickness=1)
        self.app = app

    def title(self, text):
        tk.Label(self, text=text, font=FONT_BOLD, bg=SURFACE, fg=TEXT, anchor="e", justify="right").pack(
            fill="x", padx=20, pady=(20, 4)
        )

    def hint(self, text):
        tk.Label(
            self, text=text, font=FONT_NORMAL, bg=SURFACE, fg=MUTED, anchor="e", justify="right", wraplength=480
        ).pack(fill="x", padx=20, pady=(0, 12))

    def primary_button(self, text, command):
        btn = tk.Button(
            self, text=text, font=FONT_BOLD, bg=ACCENT, fg="#1C1403",
            activebackground="#F0C465", relief="flat", command=command, cursor="hand2", pady=10,
        )
        btn.pack(fill="x", padx=20, pady=(10, 20))
        return btn


# ---------------- خطوة ٠: التحقق من الدولة (قبل أي شي) ----------------

class GeoCheckFrame(StyledFrame):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.title("جارِ التحقق من التوفر بمنطقتك")
        self.status_label = tk.Label(
            self, text="يرجى الانتظار...", font=FONT_NORMAL, bg=SURFACE, fg=MUTED, anchor="e"
        )
        self.status_label.pack(fill="x", padx=20, pady=20)
        self.spinner = ttk.Progressbar(self, mode="indeterminate")
        self.spinner.pack(fill="x", padx=20, pady=(0, 20))

    def on_show(self):
        self.spinner.start(12)
        self.status_label.config(text="جارِ التحقق من التوفر بمنطقتك...")
        threading.Thread(target=self.worker, daemon=True).start()

    def worker(self):
        allowed, code, message = geo_check.check_access()
        self.after(0, lambda: self.on_result(allowed, code, message))

    def on_result(self, allowed, code, message):
        self.spinner.stop()
        if allowed:
            self.app.show_frame(DomainFrame)
        else:
            self.app.frames[BlockedFrame].set_message(message)
            self.app.show_frame(BlockedFrame)


class BlockedFrame(StyledFrame):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.title("البرنامج غير متاح بمنطقتك حالياً")
        self.message_label = tk.Label(
            self, text="", font=FONT_NORMAL, bg=SURFACE, fg=DANGER, anchor="e", justify="right", wraplength=480
        )
        self.message_label.pack(fill="x", padx=20, pady=20)
        self.primary_button("حاول مرة ثانية", self.on_retry)

    def set_message(self, message):
        self.message_label.config(text=message)

    def on_retry(self):
        self.app.show_frame(GeoCheckFrame)


# ---------------- خطوة ١: إدخال الدومين ----------------

class DomainFrame(StyledFrame):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.title("١. أدخل نطاق موقعك")
        self.hint("فقط المواقع التي تملكها أو عندك إذن صريح بفحصها.")

        self.domain_entry = tk.Entry(self, font=FONT_NORMAL, justify="right", bg=BG, fg=TEXT, insertbackground=TEXT)
        self.domain_entry.pack(fill="x", padx=20, pady=(0, 10))
        self.domain_entry.insert(0, "example.com")

        self.method_var = tk.StringVar(value="file")
        method_row = tk.Frame(self, bg=SURFACE)
        method_row.pack(fill="x", padx=20, pady=(0, 10))
        tk.Radiobutton(method_row, text="رفع ملف تحقق", variable=self.method_var, value="file",
                        bg=SURFACE, fg=TEXT, selectcolor=BG, font=FONT_NORMAL, anchor="e").pack(side="right", padx=5)
        tk.Radiobutton(method_row, text="سجل DNS", variable=self.method_var, value="dns",
                        bg=SURFACE, fg=TEXT, selectcolor=BG, font=FONT_NORMAL, anchor="e").pack(side="right", padx=5)

        self.error_label = tk.Label(self, text="", font=FONT_NORMAL, bg=SURFACE, fg=DANGER, anchor="e")
        self.error_label.pack(fill="x", padx=20)

        self.primary_button("متابعة للتحقق من الملكية", self.on_continue)

    def on_continue(self):
        domain = self.domain_entry.get().strip().lower()
        if not domain or "." not in domain:
            self.error_label.config(text="أدخل نطاق صحيح، مثل: example.com")
            return

        can_scan, remaining = local_log.can_scan_today()
        if not can_scan:
            self.error_label.config(text=f"وصلت للحد الأقصى ({local_log.MAX_SCANS_PER_DAY} فحوصات باليوم). حاول باكر.")
            return

        blocked, reason = blocklist.is_domain_blocked(domain)
        if blocked:
            self.error_label.config(text=f"ما ينفحص هذا النطاق: {reason}")
            return

        self.error_label.config(text="")
        self.app.state["domain"] = domain
        self.app.state["method"] = self.method_var.get()
        self.app.state["token"] = verification.generate_token()
        self.app.show_frame(VerifyFrame)


# ---------------- خطوة ٢: التحقق من الملكية ----------------

class VerifyFrame(StyledFrame):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.title("٢. أثبت ملكيتك للموقع")
        self.instructions_label = tk.Label(
            self, text="", font=FONT_NORMAL, bg=SURFACE, fg=MUTED, anchor="e", justify="right", wraplength=480
        )
        self.instructions_label.pack(fill="x", padx=20, pady=(0, 10))

        self.token_box = tk.Label(
            self, text="", font=("Consolas", 10), bg=BG, fg=ACCENT, wraplength=480, justify="left", pady=12
        )
        self.token_box.pack(fill="x", padx=20, pady=(0, 16))

        self.status_label = tk.Label(self, text="", font=FONT_NORMAL, bg=SURFACE, fg=SUCCESS, anchor="e")
        self.status_label.pack(fill="x", padx=20)

        self.primary_button("تحققت، تأكد الآن", self.on_check)

    def on_show(self):
        domain = self.app.state["domain"]
        method = self.app.state["method"]
        token = self.app.state["token"]
        if method == "file":
            self.instructions_label.config(
                text=f"أنشئ ملف بالمسار /.well-known/scanshield-verify.txt على موقعك، وحط بداخله النص التالي:"
            )
        else:
            self.instructions_label.config(text="أضف سجل TXT جديد بإعدادات DNS لنطاقك بالقيمة التالية:")
        self.token_box.config(text=token)
        self.status_label.config(text="")

    def on_check(self):
        self.status_label.config(text="جارِ التحقق...", fg=MUTED)
        self.update_idletasks()

        domain = self.app.state["domain"]
        method = self.app.state["method"]
        token = self.app.state["token"]

        def worker():
            ok = verification.check_verification(domain, token, method)
            self.after(0, lambda: self.on_result(ok))

        threading.Thread(target=worker, daemon=True).start()

    def on_result(self, ok):
        if ok:
            self.status_label.config(text="✓ تم التحقق من ملكية النطاق", fg=SUCCESS)
            self.after(500, lambda: self.app.show_frame(ConsentFrame))
        else:
            self.status_label.config(text="لم يتم العثور على التحقق بعد. تأكد من الخطوات وحاول مرة ثانية.", fg=DANGER)


# ---------------- خطوة ٣: الموافقة ----------------

class ConsentFrame(StyledFrame):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.title("٣. إقرار المسؤولية")

        text_box = tk.Text(
            self, font=FONT_NORMAL, bg=BG, fg=MUTED, wrap="word", height=7,
            relief="flat", padx=12, pady=12,
        )
        text_box.insert("1.0", config.CONSENT_TEXT)
        text_box.tag_configure("right", justify="right")
        text_box.tag_add("right", "1.0", "end")
        text_box.config(state="disabled")
        text_box.pack(fill="x", padx=20, pady=(0, 14))

        self.consent_var = tk.BooleanVar(value=False)
        check_row = tk.Frame(self, bg=SURFACE)
        check_row.pack(fill="x", padx=20, pady=(0, 10))
        tk.Checkbutton(
            check_row, text="أقرأت وأوافق على ما ورد أعلاه، وأتحمل كامل المسؤولية",
            variable=self.consent_var, bg=SURFACE, fg=TEXT, selectcolor=BG, font=FONT_NORMAL,
            anchor="e", command=self.on_toggle,
        ).pack(anchor="e")

        self.start_btn = self.primary_button("ابدأ الفحص", self.on_start)
        self.start_btn.config(state="disabled", bg="#1C3A33", fg=MUTED)

    def on_toggle(self):
        if self.consent_var.get():
            self.start_btn.config(state="normal", bg=ACCENT, fg="#1C1403")
        else:
            self.start_btn.config(state="disabled", bg="#1C3A33", fg=MUTED)

    def on_start(self):
        local_log.record_scan(self.app.state["domain"], self.app.state["method"], config.CONSENT_VERSION)
        self.app.show_frame(ResultsFrame)


# ---------------- خطوة ٤: النتائج ----------------

class ResultsFrame(StyledFrame):
    def __init__(self, parent, app):
        super().__init__(parent, app)
        self.title("٤. نتائج الفحص")

        self.progress_label = tk.Label(self, text="", font=FONT_NORMAL, bg=SURFACE, fg=MUTED, anchor="e")
        self.progress_label.pack(fill="x", padx=20, pady=(0, 6))

        self.progress_bar = ttk.Progressbar(self, mode="determinate")
        self.progress_bar.pack(fill="x", padx=20, pady=(0, 14))

        canvas_frame = tk.Frame(self, bg=SURFACE)
        canvas_frame.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        self.canvas = tk.Canvas(canvas_frame, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(canvas_frame, orient="vertical", command=self.canvas.yview)
        self.results_container = tk.Frame(self.canvas, bg=BG)

        self.results_container.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.create_window((0, 0), window=self.results_container, anchor="nw", width=480)
        self.canvas.configure(yscrollcommand=scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        btn_row = tk.Frame(self, bg=SURFACE)
        btn_row.pack(fill="x", padx=20, pady=(0, 16))

        self.export_btn = tk.Button(
            btn_row, text="💾 حفظ التقرير", font=FONT_NORMAL, bg="#1C3A33", fg=MUTED,
            relief="flat", command=self.on_export_report, cursor="hand2", state="disabled",
        )
        self.export_btn.pack(side="right", padx=(8, 0), ipadx=8, ipady=4)

        tk.Button(
            btn_row, text="فحص موقع ثاني", font=FONT_NORMAL, bg=SURFACE, fg=ACCENT,
            relief="flat", command=self.on_new_scan, cursor="hand2",
        ).pack(side="right", ipadx=8, ipady=4)

        self.collected_results = {}
        self.grade_card = None

    def on_show(self):
        for widget in self.results_container.winfo_children():
            widget.destroy()
        self.progress_bar["value"] = 0
        self.progress_label.config(text="جارِ تشغيل الفحوصات...")
        self.total_steps = 70  # تقريبي لعدد خطوات التقدم الكلية بين كل الفحوصات
        self.done_steps = 0
        self.collected_results = {}
        self.grade_card = None
        self.export_btn.config(state="disabled", bg="#1C3A33", fg=MUTED)

        domain = self.app.state["domain"]
        threading.Thread(target=self.run_scans, args=(domain,), daemon=True).start()

    def bump_progress(self):
        self.done_steps += 1
        pct = min(100, int((self.done_steps / self.total_steps) * 100))
        self.after(0, lambda: self.progress_bar.config(value=pct))

    def run_scans(self, domain):
        for key, label, module in ALL_SCANNERS:
            self.after(0, lambda l=label: self.progress_label.config(text=f"جارِ تشغيل: {l}..."))
            try:
                result = module.run(domain, progress_callback=self.bump_progress)
            except Exception as e:
                result = {"tool": label, "status": "failed", "error": str(e)}
            self.collected_results[key] = result
            self.after(0, lambda r=result: self.add_result_card(r))

        self.after(0, self.on_all_done)

    def on_all_done(self):
        self.progress_label.config(text="اكتمل الفحص ✓")
        self.progress_bar.config(value=100)
        self.show_grade_card()
        self.export_btn.config(state="normal", bg=ACCENT, fg="#1C1403")

    def show_grade_card(self):
        grade_info = scoring.calculate(self.collected_results)
        self.last_grade_info = grade_info

        card = tk.Frame(self.results_container, bg=SURFACE, highlightbackground=grade_info["color"], highlightthickness=2)

        tk.Label(card, text=grade_info["grade"], font=("Segoe UI", 40, "bold"), bg=SURFACE, fg=grade_info["color"]).pack(pady=(14, 0))
        tk.Label(card, text=grade_info["label"], font=FONT_BOLD, bg=SURFACE, fg=grade_info["color"]).pack()
        tk.Label(card, text=f"النتيجة: {grade_info['score']}/100", font=FONT_NORMAL, bg=SURFACE, fg=MUTED).pack(pady=(2, 10))

        if grade_info["top_reasons"]:
            reasons_frame = tk.Frame(card, bg=SURFACE)
            reasons_frame.pack(fill="x", padx=16, pady=(0, 14))
            for reason in grade_info["top_reasons"]:
                tk.Label(
                    reasons_frame, text=f"• {reason}", font=("Segoe UI", 9), bg=SURFACE, fg=ACCENT,
                    anchor="e", justify="right", wraplength=440,
                ).pack(fill="x")

        children = self.results_container.winfo_children()
        if children:
            card.pack(fill="x", pady=(0, 10), padx=2, before=children[0])
        else:
            card.pack(fill="x", pady=(0, 10), padx=2)
        self.grade_card = card

    def on_export_report(self):
        if not self.collected_results:
            return
        domain = self.app.state["domain"]
        grade_info = getattr(self, "last_grade_info", scoring.calculate(self.collected_results))

        desktop = Path.home() / "Desktop"
        if not desktop.exists():
            desktop = Path.home()
        filename = f"ScanShield_Report_{domain}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        out_path = desktop / filename

        try:
            report_export.export_report(domain, self.collected_results, grade_info, out_path)
        except Exception as e:
            messagebox.showerror("خطأ", f"تعذر حفظ التقرير: {e}")
            return

        try:
            os.startfile(str(out_path))  # noqa: يشتغل بس على ويندوز
        except AttributeError:
            try:
                subprocess.run(["xdg-open", str(out_path)], check=False)
            except Exception:
                pass

        messagebox.showinfo("تم الحفظ", f"التقرير انحفظ بسطح المكتب:\n{filename}")

    def add_result_card(self, result):
        card = tk.Frame(self.results_container, bg=SURFACE, highlightbackground="#2A4A42", highlightthickness=1)
        card.pack(fill="x", pady=6, padx=2)

        status = result.get("status", "unknown")
        status_color = {"completed": SUCCESS, "failed": DANGER}.get(status, MUTED)

        header = tk.Frame(card, bg=SURFACE)
        header.pack(fill="x", padx=12, pady=(10, 4))
        tk.Label(header, text=status, font=("Segoe UI", 8), bg=SURFACE, fg=status_color).pack(side="left")
        tk.Label(header, text=result.get("tool", "؟"), font=FONT_BOLD, bg=SURFACE, fg=TEXT).pack(side="right")

        summary = result.get("summary") or result.get("error") or ""
        if summary:
            tk.Label(
                card, text=summary, font=FONT_NORMAL, bg=SURFACE, fg=MUTED, anchor="e",
                justify="right", wraplength=440,
            ).pack(fill="x", padx=12, pady=(0, 10))

    def on_new_scan(self):
        self.app.state = {"domain": None, "method": None, "token": None}
        self.app.show_frame(DomainFrame)


if __name__ == "__main__":
    app = ScanShieldApp()
    app.mainloop()
