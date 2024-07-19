# shufflebox

### Description

```
I've learned that if you shuffle your text, it's 
elrlay hrda to tlle htaw eht nioiglra nutpi aws.

Find the text censored with question marks in output_censored.txt and 
surround it with DUCTF{}.

Author: hashkitten

```

### Files&#x20;

* output\_censored.txt

```
aaaabbbbccccdddd -> ccaccdabdbdbbada
abcdabcdabcdabcd -> bcaadbdcdbcdacab
???????????????? -> owuwspdgrtejiiud
```

* shufflebox.py

```python
import random

PERM = list(range(16))
random.shuffle(PERM)

def apply_perm(s):
	assert len(s) == 16
	return ''.join(s[PERM[p]] for p in range(16))

for line in open(0):
	line = line.strip()
	print(line, '->', apply_perm(line))
```
