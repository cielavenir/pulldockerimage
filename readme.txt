## Article

https://qiita.com/cielavenir/items/c7e9db24dc6e4578e3c8

## Usage

```
pulldockerimage host/repository:tag > archive.tar
eg: index.docker.io/library/ubuntu:devel > ubuntu.tar

generate a docker image directly (without deploying to the client machine).

`docker login` is required prior. .docker/config.json should look like this.

{
        "auths": {
                "index.docker.io": {
                        "auth": base64(username:password)
                }
        }
}
```
