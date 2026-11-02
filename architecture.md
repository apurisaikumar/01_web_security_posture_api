# Architecture

```text
Client -> FastAPI request validation -> Scope validation -> HTTP client
                                                     |
                                                     v
                                  Header and cookie configuration checks
                                                     |
                                                     v
                                      Severity / evidence / remediation
                                                     |
                                                     v
                                             JSON assessment
```

The scope check runs before outbound HTTP requests. TLS certificate verification remains enabled. Redirect following is disabled to reduce the risk of silently leaving the requested target scope.
