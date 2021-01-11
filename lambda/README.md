# Lambda Util

This sub folder contains helper functions for writing go lambda functions on the threat team.

## Standard utils

In each lambda you will want to do some common tasks.  Tasks like logging things, callings APIs, and checking a user's SSO groups.  Instead of writing this code yourself every time, or duplicating your code, you can call this library get a "toolbox" you can use.

Get the toolbox by calling `toolbox.GetToolbox()`

## AWS

### Getting something from the parameter store

You can use the toolbox function `GetFromParameterStore()` to get a parameter from the parameter store.  Ex:

```go
t := toolbox.GetToolbox()
t.LoadSession(context.Background(), credentials.NewEnvCredentials(), "us-west-2")
parameter, err := t.GetFromParameterStore(context.Background(), "TestParameter", false)
```

### Encryption

To encrypt something you can use the toolbox `Encrypt` and `Decrypt` functions.

## Authorization

### Checking AD groups in your lambda

You can use the toolbox to check the jomax active directory groups of a user.

```go
groups, err := toolbox.ValidateJWT(ctx, MyJWT)
```

### Check JWT creation data

It is the expectation that once your Lambada is invoked, the user has a valid JWT created in the last `90` days (TODO).  However, if you want to check the lambda was created more recently (for more sensitive endpoints) you can do so with the toolbox.

First validate and retrieve the token.

```go
token, _ := toolbox.ValidateJWT(ctx, jwt)
```

Then you can check it's expiration using standard GoDaddy levels, or a custom date.

### Using standard GoDaddy Levels

You can check if the token is expired based on standard GoDaddy levels using the token function `IsExpired`.

```go
token.IsExpired(gdtoken.Medium)
```

### Checking for custom date

You check the token is newer than your own custom date requirement by checking `token.IssuedAtTime` and `token.VerifiedAtTime`.  Note that there is a difference if the JWT is "persistent" or not.  You can check that with `token.IsPersistentJwt`.

## Tracing

To support tracing in your lambda, you must extend your application’s code to report trace data to Elastic APM.

There are built in instrumentation modules, and also custom instrumentations.  See [this document](https://www.elastic.co/guide/en/apm/agent/go/master/getting-started.html) for more details.

Note that the following env vars must be set.

* ELASTIC_APM_SERVER_URL

Optionally:

* ELASTIC_APM_API_KEY
* ELASTIC_APM_SECRET_TOKEN
* ELASTIC_APM_VERIFY_SERVER_CERT

### APM Lambda module

The `apmlambda` package intercepts requests to lambda function invocations.  Make sure you include this import in each lambda you write.

```go
import (
    _ "go.elastic.co/apm/module/apmlambda"
)
```

### APM HTTP module

One of the built in modules is middleware for the `net/http` package.  This module can wrap the `http.Client` and `http.Handler` objects.  Here is an example of using the toolbox to get a trace-enabled http client

```go
toolbox := toolbox.GetToolbox().GetHTTPClient(nil)
```

## Example lambda

There is a simple example `helloworld` lambda in this directory.  If you're looking for something more built out, here is a [bigger example](https://github.com/aws/aws-sam-cli/tree/382a81483a6bf616e6d30490c0fa433cabeb6555/samcli/lib/init/templates/cookiecutter-aws-sam-hello-golang/%7B%7Bcookiecutter.project_name%7D%7D)

## Calling your lambda locally

First build your lambda.

(in this repo's example):

```sh
GOOS=linux GOARCH=amd64 go build -o helloworld/helloworld ./helloworld
```

You now have your linux-ready binary that will actually be called in the lambda.

Next you must create your `template.yml`.  This file defines your lambda resources and where they are located locally.  You can see information how to create this file [here](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-specification-template-anatomy.html).  There is an example `template.yml` file in this repository that corresponds to the example lambda.

After you have your `template.yml`, you need to invoke your lambda.  You can invoke lambda functions programatically with [this go library](https://github.com/djhworld/go-lambda-invoke), or you can use the [AWS sam CLI (recommended)](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install-mac.html).

Here is the `sam` command usage:

```sh
sam local invoke [OPTIONS]
```

To run our example:

```sh
sam local invoke "HelloWorld" --no-event
```

Output:

![lambda run](./doc/lambda_run.png)

You can see more instructions on how to use `sam` [on the documentation page](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-local-invoke.html) or on the [examples page](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-using-invoke.html).
