# dsh-plugin-license-manager — License Manager

Gestor de licencias para DeepSeek Harness: genera, verifica y revoca claves HMAC locales para apps y bots de WENDIGO, con vencimientos y almacenamiento local.

## Herramientas

Ver `docs/COMO-FUNCIONA.md` para el detalle.

## Instalación

Desde **DSH → Settings → Plugins** instala `github:thegabopacheco-sudo/dsh-plugin-license-manager` y permite el script de instalación.

```
dsh plugin --profile <perfil> add github:thegabopacheco-sudo/dsh-plugin-license-manager
```

## Seguridad

- Lectura por defecto; escritura solo con `confirm:true` y pedido explícito.
- `DSH_LICENSE_MANAGER_MODE=read-only` desactiva acciones.
- Listas blancas y auditoría en `<DSH_HOME>\cache\license-manager\audit.jsonl`.

## Licencia

MIT © thegabopacheco-sudo
