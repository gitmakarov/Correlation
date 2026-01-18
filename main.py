import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import phonenumbers
from phonenumbers import carrier, geocoder, timezone
import requests
import dns.resolver
import socket
import re
import os


class CorrelationApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Correlation - BETA 1.0.0")
        self.root.geometry("800x600")
        self.root.minsize(600, 400)
        
        self.bg_color = "#121212"
        self.fg_color = "#FFFFFF"
        self.btn_bg = "#2D2D2D"
        self.btn_fg = "#FFFFFF"
        self.btn_hover = "#3A3A3A"
        self.result_bg = "#1E1E1E"
        self.border_color = "#333333"
        
        self.root.configure(bg=self.bg_color)
        
        self.main_frame = tk.Frame(root, bg=self.bg_color, padx=15, pady=15)
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        
        self.create_main_menu()

    def create_main_menu(self):
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        
        title_label = tk.Label(
            self.main_frame,
            text="Correlation",
            font=("Segoe UI", 20, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 5))
        
        version_label = tk.Label(
            self.main_frame,
            text="Версия - BETA 1.0.0",
            font=("Segoe UI", 10),
            bg=self.bg_color,
            fg="#AAAAAA"
        )
        version_label.grid(row=1, column=0, columnspan=3, pady=(0, 20))
        
        instruction_label = tk.Label(
            self.main_frame,
            text="Выберите инструмент:",
            font=("Segoe UI", 12),
            bg=self.bg_color,
            fg=self.fg_color
        )
        instruction_label.grid(row=2, column=0, columnspan=3, pady=(0, 20))
        
        buttons = [
            ("📱 Phone Lookup", self.phone_lookup),
            ("📧 Email Lookup", self.email_lookup),
            ("🌐 IP Lookup", self.ip_lookup),
            ("🌍 Domain Lookup", self.domain_lookup),
            ("🧩 ASN Info", self.asn_lookup),
            ("📄 File Metadata (Soon)", None) 
        ]
        
        row = 3
        col = 0
        for text, command in buttons:
            btn = tk.Button(
                self.main_frame,
                text=text,
                font=("Segoe UI", 11),
                bg=self.btn_bg,
                fg=self.btn_fg,
                relief=tk.FLAT,
                padx=15,
                pady=10,
                width=20,
                cursor="hand2",
                state="normal" if command else "disabled"
            )
            
            if command:
                btn.bind("<Enter>", lambda e, b=btn: b.config(bg=self.btn_hover))
                btn.bind("<Leave>", lambda e, b=btn: b.config(bg=self.btn_bg))
                btn.config(command=command)
            
            btn.grid(row=row, column=col, padx=10, pady=5, sticky="nsew")
            
            col += 1
            if col > 1:
                col = 0
                row += 1
        
        channel_btn = tk.Button(
            self.main_frame,
            text="📢 Наш канал",
            font=("Segoe UI", 11),
            bg="#FF6B6B",
            fg="white",
            relief=tk.FLAT,
            padx=15,
            pady=10,
            width=20,
            cursor="hand2",
            command=self.open_channel
        )
        channel_btn.grid(row=row, column=0, columnspan=2, padx=10, pady=20, sticky="nsew")

        for i in range(3):
            self.main_frame.columnconfigure(i, weight=1)

    def open_channel(self):
        import webbrowser
        webbrowser.open("https://t.me/+Yl3ML5MyeLllZTRl")

    def show_input_form(self, prompt, callback):
        for widget in self.main_frame.winfo_children():
            widget.destroy()

        back_btn = tk.Button(
            self.main_frame,
            text="⬅ Назад",
            font=("Segoe UI", 10),
            bg=self.btn_bg,
            fg=self.fg_color,
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.create_main_menu,
            cursor="hand2"
        )
        back_btn.grid(row=0, column=0, sticky="nw", padx=5, pady=5)

        prompt_label = tk.Label(
            self.main_frame,
            text=prompt,
            font=("Segoe UI", 12),
            bg=self.bg_color,
            fg=self.fg_color
        )
        prompt_label.grid(row=1, column=0, columnspan=2, pady=(10, 5), sticky="w")

        self.input_entry = tk.Entry(
            self.main_frame,
            font=("Segoe UI", 12),
            bg=self.result_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color,
            relief=tk.SUNKEN,
            bd=2,
            highlightthickness=1,
            highlightbackground=self.border_color,
            width=40
        )
        self.input_entry.grid(row=2, column=0, columnspan=2, pady=10, padx=10, sticky="ew")
        self.input_entry.focus()

        send_btn = tk.Button(
            self.main_frame,
            text="Отправить",
            font=("Segoe UI", 12, "bold"),
            bg="#007ACC",
            fg="white",
            relief=tk.FLAT,
            padx=15,
            pady=8,
            cursor="hand2"
        )
        send_btn.bind("<Enter>", lambda e: send_btn.config(bg="#005FA3"))
        send_btn.bind("<Leave>", lambda e: send_btn.config(bg="#007ACC"))
        send_btn.config(command=lambda: callback(self.input_entry.get()))
        send_btn.grid(row=3, column=0, columnspan=2, pady=15)

        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)

    def phone_lookup(self):
        self.show_input_form("Введите номер телефона (в международном формате):", self.process_phone)

    def email_lookup(self):
        self.show_input_form("Введите email адрес:", self.process_email)

    def ip_lookup(self):
        self.show_input_form("Введите IP адрес:", self.process_ip)

    def domain_lookup(self):
        self.show_input_form("Введите доменное имя:", self.process_domain)

    def asn_lookup(self):
        self.show_input_form("Введите ASN (например, AS12345):", self.process_asn)

    def process_phone(self, text):
        try:
            parsed_number = phonenumbers.parse(text, None)
            
            if not phonenumbers.is_valid_number(parsed_number):
                self.show_error("❌ Неверный формат номера телефона")
                return

            country = geocoder.description_for_number(parsed_number, "ru")
            operator = carrier.name_for_number(parsed_number, "ru")
            timezones = timezone.time_zones_for_number(parsed_number)
            number_type = phonenumbers.number_type(parsed_number)

            type_map = {
                phonenumbers.PhoneNumberType.MOBILE: "Мобильный",
                phonenumbers.PhoneNumberType.FIXED_LINE: "Стационарный",
                phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Стационарный/Мобильный",
                phonenumbers.PhoneNumberType.TOLL_FREE: "Бесплатный",
                phonenumbers.PhoneNumberType.PREMIUM_RATE: "Премиум",
                phonenumbers.PhoneNumberType.UNKNOWN: "Неизвестный"
            }
            
            result = (
                f"📱 Информация о номере:\n\n"
                f"📞 Номер: {phonenumbers.format_number(parsed_number, phonenumbers.PhoneNumberFormat.INTERNATIONAL)}\n"
                f"🌍 Страна: {country}\n"
                f"🏢 Оператор: {operator}\n"
                f"🏷 Тип: {type_map.get(number_type, 'Неизвестный')}\n"
                f"🕐 Часовые пояса: {', '.join(timezones)}"
            )
            
            self.show_result(result)
            
        except phonenumbers.NumberParseException:
            self.show_error("❌ Неверный формат номера телефона")
        except Exception as e:
            self.show_error(f"❌ Ошибка при обработке: {str(e)}")

    def process_email(self, text):
        text = text.lower().strip()
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", text):
            self.show_error("❌ Неверный формат email адреса")
            return

        domain = text.split("@")[1]
        is_disposable = self.is_disposable_email(text)
        mx_records = self.get_mx_records(domain)
        
        result = (
            f"📧 Информация об email:\n\n"
            f"✉️ Адрес: {text}\n"
            f"🌍 Домен: {domain}\n"
            f"🎭 Временный: {'Да' if is_disposable else 'Нет'}\n"
            f"📡 MX записи:\n"
        )
        
        if mx_records:
            for record in mx_records:
                result += f"  • {record}\n"
        else:
            result += "  • Не найдены\n"
        
        self.show_result(result)

    def process_ip(self, text):
        text = text.strip()
        
        try:
            socket.inet_aton(text)
        except socket.error:
            self.show_error("❌ Неверный формат IP адреса")
            return

        try:
            response = requests.get(f"http://ipwho.is/{text}")
            data = response.json()
            
            is_proxy = self.is_proxy_ip(text)
            
            result = (
                f"🌐 Информация об IP:\n\n"
                f"🔢 IP: {data.get('ip', 'N/A')}\n"
                f"🌍 Страна: {data.get('country', 'N/A')} ({data.get('country_code', 'N/A')})\n"
                f"🏙️ Город: {data.get('city', 'N/A')}\n"
                f"🏢 ISP: {data.get('connection', {}).get('isp', 'N/A')}\n"
                f"🔢 ASN: {data.get('connection', {}).get('asn', 'N/A')}\n"
                f"🏷 Тип: {data.get('type', 'N/A')}\n"
                f"🎭 Прокси/Хостинг: {'Да' if is_proxy else 'Нет'}"
            )
            
            self.show_result(result)
            
        except Exception as e:
            self.show_error(f"❌ Ошибка при получении данных: {str(e)}")

    def process_domain(self, text):
        text = text.strip().lower()
        
        if not re.match(r"^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}$", text):
            self.show_error("❌ Неверный формат доменного имени")
            return

        try:
            whois_info = self.get_whois_info(text)
            
            result = (
                f"🌍 Информация о домене:\n\n"
                f"🌐 Домен: {text}\n"
                f"🏢 Регистратор: {whois_info['registrar']}\n"
                f"📅 Дата регистрации: {whois_info['creation_date']}\n"
                f"🔚 Дата окончания: {whois_info['expiration_date']}\n"
                f"🌍 Страна: {whois_info['country']}\n"
                f"📡 DNS серверы:\n"
            )
            
            if whois_info['name_servers']:
                for ns in whois_info['name_servers']:
                    result += f"  • {ns}\n"
            else:
                result += "  • Не найдены\n"
            
            self.show_result(result)
            
        except Exception as e:
            self.show_error(f"❌ Ошибка при получении данных: {str(e)}")

    def process_asn(self, text):
        text = text.upper().strip()
        
        if not text.startswith("AS") or not text[2:].isdigit():
            self.show_error("❌ Неверный формат ASN. Пример: AS12345")
            return

        asn_num = text[2:]
        
        try:
            response = requests.get(f"https://ipwho.is/AS{asn_num}")
            data = response.json()
            
            org_name = data.get('connection', {}).get('org', 'N/A')
            country = data.get('country', 'N/A')
            isp = data.get('connection', {}).get('isp', 'N/A')
            
            result = (
                f"🧩 Информация об ASN:\n\n"
                f"🔢 ASN: {text}\n"
                f"🏢 Организация: {org_name}\n"
                f"🌍 Страна: {country}\n"
                f"📡 ISP: {isp}"
            )
            
            self.show_result(result)
            
        except Exception as e:
            self.show_error(f"❌ Ошибка при получении данных: {str(e)}")

    def is_disposable_email(self, email: str) -> bool:
        disposable_domains = {
            "10minutemail.com", "tempmail.org", "guerrillamail.com",
            "mailinator.com", "throwawaymail.com", "dispostable.com",
            "sharklasers.com", "yopmail.com", "trashmail.com"
        }
        domain = email.split("@")[1].lower()
        return domain in disposable_domains

    def get_mx_records(self, domain: str):
        try:
            mx_records = dns.resolver.resolve(domain, 'MX')
            return [str(mx.exchange).rstrip('.') for mx in mx_records]
        except Exception:
            return []

    def get_whois_info(self, domain: str):
        try:
            import whois
            w = whois.whois(domain)
            return {
                "registrar": w.registrar or "N/A",
                "creation_date": str(w.creation_date) or "N/A",
                "expiration_date": str(w.expiration_date) or "N/A",
                "country": w.country or "N/A",
                "name_servers": w.name_servers or []
            }
        except Exception:
            pass

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("whois.verisign-grs.com", 43))
            s.send(f"{domain}\r\n".encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()
            response_str = response.decode()

            registrar = "N/A"
            creation_date = "N/A"
            expiration_date = "N/A"
            country = "N/A"

            lines = response_str.split("\n")
            for line in lines:
                if "Registrar:" in line:
                    registrar = line.split(":", 1)[1].strip()
                elif "Creation Date:" in line:
                    creation_date = line.split(":", 1)[1].strip()
                elif "Registry Expiry Date:" in line:
                    expiration_date = line.split(":", 1)[1].strip()
                elif "Registrant Country:" in line:
                    country = line.split(":", 1)[1].strip()

            return {
                "registrar": registrar,
                "creation_date": creation_date,
                "expiration_date": expiration_date,
                "country": country,
                "name_servers": []
            }
        except Exception:
            return {
                "registrar": "N/A",
                "creation_date": "N/A",
                "expiration_date": "N/A",
                "country": "N/A",
                "name_servers": []
            }

    def is_proxy_ip(self, ip: str):
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")
            data = response.json()
            return data.get("proxy", False) or data.get("hosting", False)
        except Exception:
            return False

    def show_result(self, result):
        for widget in self.main_frame.winfo_children():
            widget.destroy()
        
        # Назад
        back_btn = tk.Button(
            self.main_frame,
            text="⬅ Назад",
            font=("Segoe UI", 10),
            bg=self.btn_bg,
            fg=self.fg_color,
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=self.create_main_menu,
            cursor="hand2"
        )
        back_btn.grid(row=0, column=0, sticky="nw", padx=5, pady=5)
        
        copy_btn = tk.Button(
            self.main_frame,
            text="📋 Скопировать",
            font=("Segoe UI", 10),
            bg=self.btn_bg,
            fg=self.fg_color,
            relief=tk.FLAT,
            padx=10,
            pady=5,
            command=lambda: self.copy_to_clipboard(result),
            cursor="hand2"
        )
        copy_btn.grid(row=0, column=1, sticky="ne", padx=5, pady=5)
        
        result_title = tk.Label(
            self.main_frame,
            text="Результат:",
            font=("Segoe UI", 12, "bold"),
            bg=self.bg_color,
            fg=self.fg_color
        )
        result_title.grid(row=1, column=0, columnspan=2, pady=(10, 5), sticky="w")
        
        result_text = scrolledtext.ScrolledText(
            self.main_frame,
            wrap=tk.WORD,
            width=70,
            height=15,
            font=("Consolas", 11),
            bg=self.result_bg,
            fg=self.fg_color,
            insertbackground=self.fg_color,
            relief=tk.SUNKEN,
            bd=1,
            highlightthickness=1,
            highlightbackground=self.border_color
        )
        result_text.grid(row=2, column=0, columnspan=2, pady=10, padx=10, sticky="nsew")
        result_text.insert(tk.END, result)
        result_text.configure(state='disabled')
        
        self.main_frame.columnconfigure(0, weight=1)
        self.main_frame.columnconfigure(1, weight=1)
        self.main_frame.rowconfigure(2, weight=1)

    def show_error(self, message):
        messagebox.showerror("Ошибка", message, parent=self.root)
        self.create_main_menu()

    def copy_to_clipboard(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        messagebox.showinfo("Успешно", "Результат скопирован в буфер обмена", parent=self.root)


if __name__ == "__main__":
    root = tk.Tk()
    app = CorrelationApp(root)
    root.mainloop()
