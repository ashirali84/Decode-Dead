# Decode Dead

**A Python-based CLI tool for hash identification, dictionary-based password recovery, JWT decoding, and Flask session cookie analysis.**

Decode Dead is a lightweight command-line utility built for cybersecurity learning, CTF practice, and authorized security testing.

---

## Features

### 1. Identify

* Identify possible hash formats using pattern matching.
* Recognize JWT-like structures.
* Detect possible Flask session cookie formats.
* Display possible matches and ambiguity warnings.

### 2. Hash Crack

* Dictionary-based password recovery.
* Supports a project-local `rockyou.txt` wordlist.
* Allows custom wordlist paths.
* Supports multiple algorithm candidates.
* Displays cracking status, attempts, and matching password when found.

### 3. JWT Decode

* Decode JWT header and payload.
* Inspect standard claims such as `exp`, `iat`, `nbf`, `iss`, `sub`, and `aud`.
* Display claim information and timestamp-related findings.

**Note:** JWT signature verification is not performed.

### 4. Flask Cookie Decode

* Decode common Flask session cookie payloads.
* Handle Base64URL-encoded and compressed payloads.
* Display decoded session data.

**Note:** Cookie signature verification is not performed.

---

## Project Structure

```text
decode-dead/
├── main.py
├── README.md
├── requirements.txt
├── LICENSE
├── core/
│   ├── __init__.py
│   ├── banner.py
│   ├── menu.py
│   ├── validators.py
│   └── utils.py
├── modules/
│   ├── __init__.py
│   ├── identify/
│   ├── hash_crack/
│   ├── jwt/
│   └── flask_cookie/
├── tests/
└── wordlists/
    └── README.md
```

---

## Requirements

* Python 3
* pip
* Required Python dependencies listed in `requirements.txt`
* A wordlist for dictionary-based password recovery

Some hash algorithms may require optional dependencies.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/ashirali84/Decode-Dead.git
cd decode-dead
```


### 2. Create a virtual environment

```bash
python3 -m venv .venv
```

Activate it on Linux:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Configure the wordlist

Place your `rockyou.txt` file inside:

```text
wordlists/rockyou.txt
```

Alternatively, provide a custom wordlist path when using Hash Crack.

---

## Usage

Start Decode Dead:

```bash
python3 main.py
```

The main menu provides the following options:

```text
[1] Identify
[2] Hash Crack
[3] JWT Decode
[4] Flask Decode
[5] Exit
```

Select an option and follow the prompts.

---

## Example: Identify

Input:

```text
5d41402abc4b2a76b9719d911017c592
```

Possible output:

```text
Type: hash

Possible matches:
- MD5
- NTLM
```

A matching format does not prove which algorithm generated the hash.

---

## Example: Hash Crack

Input:

```text
Target hash:
5d41402abc4b2a76b9719d911017c592

Algorithm:
md5

Wordlist:
[Enter for default wordlist]
```

Example result:

```text
Status: found
Attempts: 60
Password: hello
Algorithm: md5
```

Results depend on whether the password exists in the selected wordlist.

---

## Running Tests

Run the automated test suite:

```bash
python3 -m pytest -v
```

The project has been tested with **43 passing automated tests** at the time of writing.

---

## Limitations

* Hash identification is based on patterns and heuristics; it cannot guarantee the exact algorithm.
* Dictionary-based recovery only finds passwords present in the selected wordlist.
* JWT decoding does not validate signatures or establish token authenticity.
* Flask cookie decoding does not verify the cookie signature or establish its origin.
* Optional algorithm support depends on installed dependencies.
* The tool is intended for local analysis and authorized security testing.

---

## Security & Responsible Use

Decode Dead is intended for educational purposes, CTFs, and authorized security assessments.

Use it only on hashes, tokens, cookies, and systems that you own or have explicit permission to test.

Do not use this tool to access accounts, recover credentials, or analyze session tokens without authorization.

---

## Contributing

Contributions, bug reports, and feature suggestions are welcome.

1. Fork the repository.
2. Create a feature branch.
3. Make your changes.
4. Run the tests.
5. Submit a pull request.

---

## License

This project is distributed under the license specified in the `LICENSE` file.

---

**Decode Dead — Learn. Analyze. Decode.**
