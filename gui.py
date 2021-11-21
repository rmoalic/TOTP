import ctypes
import json
import time
from base64 import b32decode
import tkinter as tk
from tkinter import ttk

obj = ctypes.cdll.LoadLibrary('./totp.so')

ex_TOTP = obj.TOTP
ex_TOTP.restype = ctypes.c_uint32


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
        self.period = int(secret.get("period", 30))
        self.secret = b32decode(secret.get("secret", b""))

    def next_change_in(self):
        return self.period - (int(time.time()) % self.period)

    def get_otp(self):
        return TOTP(self.secret, self.digits, 0, 0,
                    self.period, int(time.time()))


class OtpFrame(ttk.Frame):
    def __init__(self, container, otp, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        self.otp = otp
        self.thumbnail = ttk.Label(self, text=otp.thumbnail)
        self.label = ttk.Label(self, text=otp.label)
        self.otp_code = ttk.Label(self, text="")
        self.remaining_time_bar = ttk.Progressbar(self, orient=tk.HORIZONTAL, mode="determinate", maximum=self.otp.period)

        self.thumbnail.grid(row=0, column=0, rowspan=2)
        self.label.grid(row=0, column=1)
        self.otp_code.grid(row=1, column=1)
        self.remaining_time_bar.grid(row=2, column=0, columnspan=2)

        self.remaining_time_bar["length"] = 300

        next_change_in = self.otp.next_change_in()
        self.remaining_time_bar.step(self.otp.period - next_change_in)
        self.remaining_time_bar.start(1000)
        self.update(next_change_in)

    def update(self, next_update_offset=0):
        opt = self.otp.get_otp()
        leading_zeros_fix = self.otp.digits + (self.otp.digits // 3) - 1
        opt_str = format(opt, "0{},d".format(leading_zeros_fix)).replace(",", " ")
        self.otp_code.configure(text=opt_str)
        self.after(self.otp.period - next_update_offset, self.update)


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


def load():
    with open("test_data.json") as f:
        secrets = json.load(f)
        return [Otp(s) for s in secrets]


def main():
    otps = load()

    fen = tk.Tk()
    fen.title('TOTP')
    # fen.geometry('400x300')

    frame = ScrollableFrame(fen)
    frame.pack(expand=True, fill=tk.BOTH)

    for otp in otps:
        if (otp.type == "TOTP" and otp.algo == "SHA1"):
            OtpFrame(frame.scrollable_frame, otp).grid()
        else:
            print("OTP not processed {}, this programm only support TOTP with SHA1".format(otp.thumbnail))

    fen.mainloop()


if __name__ == "__main__":
    main()
