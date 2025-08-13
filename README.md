# PyHash

> **Why guess hash types when you can detect and crack them automatically?**

PyHash is a fast, multi-threaded hash cracking utility for Python 3 that detects hash types automatically and attempts to crack them using multiple online APIs and databases.  
It supports **MD5, SHA1, SHA256, SHA384, and SHA512** hashes.

---

## 🚀 Features
- **Automatic hash type detection** – no need to specify the type
- **Supports**: MD5, SHA1, SHA256, SHA384, SHA512
- **Multi-threaded cracking** for faster results
- **Extract hashes from a file or entire directory**
- **Real-time progress display**
- **Command-line interface** – simple and fast

---

## 📦 Installation

### Clone the repository
```bash
git clone https://github.com/saithatavarthi876/pyHash.git
cd pyHash
```
Install dependencies
--------pip install -r requirements.txt
(Optional) Install as a command
--------sudo make install
Now you can run pyhash from anywhere



Crack a single hash
----------------- python3 pyhash.py -s <hash_here>
Crack hashes from a file
----------------- python3 pyhash.py -f hashes.txt
Find and crack hashes from a directory
----------------- python3 pyhash.py -d /path/to/directory
Use multiple threads
---------------- python3 pyhash.py -f hashes.txt -t 10
📌 Example
python3 pyhash.py -s e10adc3949ba59abbe56e057f20f883e
