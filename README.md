# ssl_manager
## Self-hosted service for creating SSL certificates

If you've ever tried creating a multi-domain certificate from IIS, you'll be aware of what a[ colossal pain in the ass it is](https://technet.microsoft.com/en-us/library/ff625722(v=ws.10).aspx). The default solution, of using a machine with an OpenSSL command line, is still [unreasonably complicated](http://security.stackexchange.com/questions/74345/provide-subjectaltname-to-openssl-directly-on-command-line).

Several online solutions have emerged, but are fatally flawed - generating SSL keys on a foreign server a terrible practice.

This application allows you to self-host a wizard that creates certificates.

# Setup

This application completely outsources security. That is, you are intended to run it on a local machine, or behind an authenticated, SSL-offloading proxy. Note this application does not store or write keys to disk on the server. To use, first, clone the repository:

```
git clone https://github.com/technion/ssl_manager.git
```

You will now need to create and edit a basic configuration file. The most important setting is the secret, which will be the default encryption key on downloaded key files. With this complete, simply start the application:

```
cp ssl_manager_config.json-example ssl_manager_config.json
vim ssl_manager_config.json
rackup -p 4567 [-o 0.0.0.0]
```

For an enterprise-grade production, we recommend JRuby:
```
RACK_ENV=production jruby -S rackup -s Puma
```

Finally, visit the running page in your browser.
