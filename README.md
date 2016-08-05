# ssl_manager
*WIP*

Self-hosted service for creating SSL certificates

If you've ever tried creating a multi-domain certificate from IIS, you'll be aware of what a pain in the ass it is.

Several online solutions have emerged, but are fatally flawed - giving a server access to your SSL keys is a terrible practice.

This application allows you to self-host a wizard that creates certificates.

# Starting application

```
rackup -p 4567 -o 0.0.0.0
```

