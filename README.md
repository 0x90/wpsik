# wpsik
WPS scan and pwn tool


##  Setup

Easy installation in one line:
```
pip install "git+https://github.com/0x90/wpsik/#egg=wpsik"
```

Install package as developer

```
git clone https://github.com/0x90/wpsik/
cd wpsik
pip install -e .
```


## Usage

wpsik is easy to use program 

```
wpsik [general_options] <mode> [options_for_mode]
```


User in two modes: scan, pwn. Example
```
wpsik scan -i wlan0mon
```