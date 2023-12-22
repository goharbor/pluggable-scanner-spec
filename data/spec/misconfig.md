# Data spec for misconfig

## Mime type

application/vnd.security.misconfig.report; version=1.0

## Report data model

-> described by json schema

```
{
  "title": "misconfig report",
  "type": "object",
  "properties": {
    "config_name": {
      "description": "The config name which being analysed",
      "type": "string"
    },
    "value": {
      "description": "The config's value",
      "type": "string"
    },
    "risk_level": {
      "type": "integer",
      "minimum": 0,
      "maximum": 3,
      "description": "The risk level of config value. 0 means safe, 1 means low risk level, 2 means middle risk level, 3 means high risk level"
    },
    "suggestion": {
      "description": "Describe why config's value has riks and provide config suggestion",
      "type": "string"
    }
  }
}
```