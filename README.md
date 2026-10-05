<div align="center">

# htb-labs

**Detailed writeups and documentation for Hack The Box labs, published once they retire.**
</div>

---

## About This Repository

This repository is my personal collection of writeups for Hack The Box labs, with a heavy focus on **Sherlocks**.

### How I work

- **I only play ACTIVE labs.** I don't like doing labs that are already retired, so I solve them while they're still live on the platform.
- **I only publish after retirement.** A writeup goes up here the moment its lab retires, never before. This keeps the repo within HTB's rules and keeps the challenge fair for everyone still solving it.
- **Sherlocks are my main focus.** They're where I spend most of my time, building real defensive skills in DFIR, threat hunting and threat intelligence.
- **I also do CTFs (mostly retired ones).** The goal here is to learn the attacker mindset. Understanding how an attacker thinks makes me better at spotting what they leave behind.

---

## Quick Links

### Sherlocks

#### Threat Intelligence

| Lab | Difficulty | Solve Date | Writeup |
| :--- | :---: | :---: | :---: |
| **FortySeven-1** | Very Easy | 08/02/2026 | [Read →](Sherlocks/FortySeven-1/README.md) |

#### DFIR

| Lab | Difficulty | Solve Date | Writeup |
| :--- | :---: | :---: | :---: |
| **Fruitzy** | Easy | 08/17/2026 | [Read →](Sherlocks/Fruitzy/README.md) |

#### Threat Hunting

| Lab | Difficulty | Solve Date | Writeup |
| :--- | :---: | :---: | :---: |
| *Coming soon* | - | - | - |

### CTFs

| Machine | Writeup |
| :--- | :---: |
| **Cap** | [Read →](CTFs/Cap) |

---

## Tools I Use for Sherlocks

| Tool | Used for |
| :--- | :--- |
| [**Volatility 3**](https://github.com/volatilityfoundation/volatility3) | Memory forensics |
| [**Autopsy**](https://www.autopsy.com/) | Disk image analysis |
| [**EZTools**](https://ericzimmerman.github.io/) (Eric Zimmerman's Tools) | Parsing artifacts such as `$MFT`, Amcache and more |
| [**Registry Explorer**](https://ericzimmerman.github.io/) | Registry hive analysis |

---

## Repository Structure

```
htb-labs/
├── Sherlocks/        # Sherlock writeups
│   ├── FortySeven-1/
│   └── Fruitzy/
├── CTFs/             # Machine writeups
│   └── Cap/
├── LICENSE
└── README.md
```

---

## Writeup Format

Each Sherlock writeup follows the same layout:

1. **Investigation details**: category, difficulty and solve date
2. **Scenario overview**: the lab's premise
3. **Task-by-task walkthrough**: the question, how I found the answer, a screenshot, and the final answer

---

## Disclaimer

These writeups are for **educational purposes only** and are published after the labs have retired, in line with Hack The Box's content policy. Please try the labs yourself first. Struggling through them is where the real learning happens.

---

<div align="center">

**Author:** [Nahokeel](https://github.com/Nahokeel)

</div>