# hydra-login-consent-go


This is a simple consent app for Hydra written in Go. It uses the Hydra SDK.
To run the example, first install Hydra, [dep](https://github.com/golang/dep)
and this project:
```
go get -u -d github.com/ory/hydra-login-consent-go
cd $GOPATH/src/github.com/ory/hydra-login-consent-go
dep ensure
```

Next open a shell and run:

Run this command in the project's directory:

```
go run main.go
```

Then, open the browser:

```
open http://localhost:3001/
```

Now follow the steps described in the browser. If you encounter an error,
use the browser's back button to get back to the last screen.

Keep in mind that you will not be able to refresh the callback url, as the
authorize code is valid only once. Also, this application needs to run on
port 4445 in order for the demo to work. 

Make sure that you stop the docker-compose demo of the Hydra main repository,
otherwise ports 4445 and 4444 are unassignable.
