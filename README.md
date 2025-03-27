
---

## 📜 APT15 YARA Rules  
### 🔍 Detecting APT15 Malware with YARA  

This repository contains a set of **YARA rules** designed to detect malware associated with **APT15 (Mirage / Ke3chang)**. The rules have been carefully crafted to identify different variants of malware used by this threat actor, including **RoyalCli, BS2005, RoyalDLL, and Exchange hijacking tools**.  

### 📌 Features  
- Covers multiple APT15 malware families.  
- Utilizes **MITRE ATT&CK** tactics and techniques.  
- Detects **backdoors, implants, and hijacking tools**.  
- Can be used with **YARA** to scan files and memory.  

### 📂 Usage  
To scan a file with YARA, use the following command:  

```sh
yara apt15_rules.yar sample.exe
```  

To scan an entire directory:  

```sh
yara -r apt15_rules.yar /path/to/directory
```  

### 🛡️ About APT15  
APT15 is a **China-linked** cyber-espionage group known for targeting government agencies, military organizations, and critical infrastructure. Their malware focuses on **stealthy persistence, data exfiltration, and command & control operations**.  

---

## 📜 قوانین YARA برای APT15  
### 🔍 شناسایی بدافزارهای APT15 با YARA  

این مخزن شامل مجموعه‌ای از **قوانین YARA** برای شناسایی بدافزارهای مرتبط با **APT15 (Mirage / Ke3chang)** است. این قوانین به دقت طراحی شده‌اند تا انواع مختلفی از بدافزارهای این گروه تهدید را شناسایی کنند، از جمله **RoyalCli, BS2005, RoyalDLL، و ابزارهای نفوذ به سرورهای Exchange**.  

### 📌 ویژگی‌ها  
- پوشش طیف گسترده‌ای از بدافزارهای APT15  
- استفاده از **تاکتیک‌ها و تکنیک‌های MITRE ATT&CK**  
- شناسایی **بکدورها، ایمپلنت‌ها و ابزارهای نفوذ**  
- قابلیت استفاده در **اسکن فایل‌ها و حافظه** با **YARA**  

### 📂 نحوه استفاده  
برای اسکن یک فایل با YARA، از دستور زیر استفاده کنید:  

```sh
yara apt15_rules.yar sample.exe
```  

برای اسکن یک پوشه کامل:  

```sh
yara -r apt15_rules.yar /path/to/directory
```  

### 🛡️ درباره APT15  
APT15 یک گروه **منتسب به چین** است که در حملات سایبری علیه **دولت‌ها، سازمان‌های نظامی و زیرساخت‌های حیاتی** فعالیت دارد. بدافزارهای این گروه بر روی **پایداری مخفیانه، استخراج داده‌ها و عملیات کنترل از راه دور** متمرکز هستند.  

---

### 📧 Contact / تماس  
For any inquiries or contributions, feel free to open an issue or pull request.  
برای هرگونه سوال یا مشارکت، می‌توانید یک **issue** یا **pull request** در گیت‌هاب ایجاد کنید.  

