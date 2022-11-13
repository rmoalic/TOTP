import json
import sys
import time
import signal
from base64 import b32decode
import tkinter as tk
from tkinter import ttk
from ctypes import cdll, c_uint32, c_char_p, c_size_t, c_uint, c_ulonglong

obj = cdll.LoadLibrary("totp.so")

ex_TOTP = obj.TOTP
ex_TOTP.restype = c_uint32
ex_TOTP.argtypes = [c_char_p, c_size_t, c_uint, c_uint, c_ulonglong, c_ulonglong, c_ulonglong]


def TOTP(secret: bytes, digits: int, algo: int,
         t0: int, tx: int, t: int) -> int:
    return ex_TOTP(secret, len(secret), digits, algo, t0, tx, t)


class Otp():

    def __init__(self, secret):
        self.thumbnail = secret.get("thumbnail", "")
        self.label = secret.get("label", "")
        self.type = secret.get("type", "TOTP")
        self.digits = int(secret.get("digits", 6))
        self.algo = secret.get("algoritm", "SHA1")
        self.t0 = int(secret.get("t0", 0))
        self.period = int(secret.get("period", 30))
        self.secret = b32decode(secret.get("secret", b""))

    def next_change_in(self):
        return self.period - ((int(time.time()) - self.t0) % self.period)

    def get_otp(self):
        algo = 0  # SHA1
        return TOTP(self.secret, self.digits, algo, self.t0,
                    self.period, int(time.time()))


class OtpFrame(ttk.Frame):
    def __init__(self, container, otp, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.otp = otp
        self.otp_str = ""
        self["style"] = "OTPFrame.TFrame"
        self.thumbnail = ttk.Label(self, text=otp.thumbnail)
        self.label = ttk.Label(self, text=otp.label, wraplength=280)
        self.otp_code = ttk.Label(self, text=self.otp_str, style="OPT.TLabel")
        self.otp_code.bind("<Button-1>", lambda e:self.to_clipboard())
        self.remaining_time_bar = ttk.Progressbar(self, orient=tk.HORIZONTAL, mode="determinate", maximum=self.otp.period, style="green.Horizontal.TProgressbar")

        self.thumbnail.grid(row=0, column=0, rowspan=2, sticky=tk.W)
        self.label.grid(row=0, column=1, sticky=tk.E)
        self.otp_code.grid(row=1, column=1, pady=10, sticky=tk.E)
        self.remaining_time_bar.grid(row=2, column=0, columnspan=2, pady=0)

        self.remaining_time_bar["length"] = 370
        self.update()

    def update(self):
        next_change_in = self.otp.next_change_in()
        self.remaining_time_bar.stop()
        self.remaining_time_bar.step(self.otp.period - next_change_in - 1)
        self.remaining_time_bar.start(1000)

        opt = self.otp.get_otp()
        leading_zeros_fix = self.otp.digits + (self.otp.digits // 3) - 1
        self.opt_str = format(opt, "0{},d".format(leading_zeros_fix)).replace(",", " ")
        self.otp_code.configure(text=self.opt_str)

        self.after(next_change_in * 1000, self.update)

    def to_clipboard(self):
        self.clipboard_clear()
        txt = self.opt_str.replace(" ", "")
        self.clipboard_append(txt)
        self.otp_code.configure(text="Copied !")
        self.after(1000, lambda: self.otp_code.configure(text=self.opt_str))


class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = tk.Canvas(self)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas)
        self.scrollable_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")


def load(file_name):
    with open(file_name) as f:
        secrets = json.load(f)
        return [Otp(s) for s in secrets]


def main():
    if len(sys.argv) < 2:
        print("USAGE: {} file_name".format(sys.argv[0]))
        exit()
    otps = load(sys.argv[1])

    fen = tk.Tk()
    fen.title("TOTP")
    fen.geometry("400x390")
    fen.resizable(False, True)
    signal.signal(signal.SIGINT, lambda x, y: fen.quit())

    tkstyle = ttk.Style(fen)

    tkstyle.configure("OTPFrame.TFrame")
    tkstyle.configure("green.Horizontal.TProgressbar", troughcolor='green', background='white')
    tkstyle.configure("OPT.TLabel", font=('Helvetica', 18), foreground="green")

    frame = ScrollableFrame(fen)
    frame.pack(expand=True, fill=tk.BOTH)

    for otp in otps:
        if (otp.type == "TOTP" and otp.algo == "SHA1"):
            f = OtpFrame(frame.scrollable_frame, otp)
            f.grid(ipady=8, padx=5)
        else:
            print("OTP not processed {}, this programm only support TOTP with SHA1".format(otp.thumbnail))

    fen.mainloop()


if __name__ == "__main__":
    main()
