# Reversing - Easy

* since the desc had easy tag on it....... i choose to use strings first

```bash
└─➜ strings easy | grep -i "pass"                                                                                                                                                        [0]
4/*A1zqi!*9Enter the passphrase:
write_bytes<libc::unix::linux_like::linux::passwd>
from_raw_parts_mut<libc::unix::linux_like::linux::passwd>
null_mut<libc::unix::linux_like::linux::passwd>
zeroed<libc::unix::linux_like::linux::passwd>
set_passcred
passcred

<--snipped-->

_ZN3std2os4unix3net6stream10UnixStream8passcred17h0bd88c1525d7fda3E
_ZN76_$LT$libc..unix..linux_like..linux..passwd$u20$as$u20$core..clone..Clone$GT$5clone17h2a8bacb431d6a862E

```



* a weird string was there before `Enter the passphrase:`
* ```
  4/*A1zqi!*9
  ```

## Flag

```bash
└─➜ ./easy                                                                                                                                                                               [0]
Enter the passphrase:
4/*A1zqi!*9
594354467b336173795f7233765f643065736e315f723371753172335f627261316e7d
```

* hmm it gives a hex code

```bash
└─➜ echo '4/*A1zqi!*9' > pass   
```

```bash
└─➜ ./easy < pass | xxd -p -r ; echo                                                                                                                                                     [0]
YCTF{3asy_r3v_d0esn1_r3qu1r3_bra1n}
```

### Flag : YCTF{3asy\_r3v\_d0esn1\_r3qu1r3\_bra1n}
