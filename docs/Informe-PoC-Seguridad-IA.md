# Seguridad en inteligencia artificial

## Vulnerabilidades OWASP y mecanismos de mitigación

### PoC de un chat conversacional de soporte

**Agente con MCP, Keycloak, OPA y Ollama**

Unidad 6 · Año 2026 · Proyecto de seguridad de infraestructura · 15 de noviembre de 2026

## Resumen

Este informe describe una prueba de concepto de chat de soporte de TI que combina un agente de lenguaje con herramientas MCP y controles explícitos de identidad y autorización. Keycloak autentica a la persona; el servidor MCP valida el token y OPA decide el acceso a cada artículo o ticket. Ollama ejecuta Qwen3.5:2b dentro de Docker Compose cuando la persona habilita el consentimiento del modelo.

La conclusión principal es que el modelo puede sugerir una consulta o preparar un ticket, pero no concede permisos ni escribe por sí solo. El BFF valida cada propuesta; MCP vuelve a autenticar y consulta OPA; la creación de un ticket requiere revisión y confirmación en la interfaz. La PoC sirve para demostrar límites de acceso y controles de agente con datos sintéticos. No es una plataforma de producción ni demuestra que un modelo sea inmune a la inyección de instrucciones.

## 1 Introducción a la seguridad en IA

Un chat de soporte con un modelo de lenguaje agrega riesgos de prompt injection, exposición de información, uso indebido de herramientas y consumo excesivo. La autenticación del usuario y las instrucciones del prompt no bastan para contener esos riesgos: las decisiones de acceso deben ocurrir en servicios de confianza, con identidad verificada y atributos del recurso consultado.

La PoC implementa un flujo acotado: responder consultas con artículos aprobados, consultar tickets propios o asignados y preparar una solicitud de soporte. Las cuentas, artículos y tickets son sintéticos. La búsqueda usa palabras clave en SQLite; no hay embeddings ni una base vectorial.

## 2 Vulnerabilidades OWASP y mitigaciones

La tabla conserva las cinco categorías del documento base, con su numeración OWASP Top 10 for LLM Applications 2025. La numeración y el orden cambian entre ediciones; no debe leerse como una equivalencia automática con la edición 2026.

| OWASP 2025 | Qué significa | Cómo se aborda en esta PoC |
|---|---|---|
| **LLM01 Prompt Injection** | Una instrucción maliciosa en el mensaje o en contenido recuperado intenta cambiar el comportamiento del modelo o inducir una acción no autorizada. | La instrucción del sistema trata mensajes y documentos como datos no confiables. El agente sólo puede proponer una herramienta de una lista fija; el BFF valida el nombre y el esquema. MCP y OPA controlan el acceso. El artículo malicioso de prueba está en cuarentena. Esto reduce el impacto, pero no garantiza resistencia frente a todo jailbreak. |
| **LLM02 Sensitive Information Disclosure** | El modelo o la aplicación pueden revelar información privada o datos pertenecientes a otra persona. | OPA evalúa la propiedad o asignación del ticket leído. Un ticket ajeno y uno inexistente producen la misma respuesta. El token no se envía al modelo y el consentimiento para Ollama se administra por separado. |
| **LLM04 Data and Model Poisoning** | Datos contaminados pueden inducir respuestas o acciones maliciosas, aunque el modelo no haya sido modificado. | La búsqueda considera artículos aprobados y MCP vuelve a evaluar cada candidato con OPA. El artículo de prueba `KB-QUARANTINE` no llega al contexto del agente. La PoC no incluye un proceso de ingestión, revisión de procedencia ni validación de fuentes. |
| **LLM06 Excessive Agency** | Un agente con permisos amplios puede ejecutar acciones de mayor alcance que las necesarias para responder. | No hay shell, SQL genérico, HTTP arbitrario ni herramientas de administración. El modelo sólo propone una acción de la lista. Crear un ticket produce un borrador editable; la confirmación genera una prueba HMAC ligada al usuario y al contenido, y MCP solicita una nueva decisión a OPA. |
| **LLM08 Vector and Embedding Weaknesses** | Los índices vectoriales pueden mezclar, recuperar o exponer fragmentos fuera del ámbito autorizado. | Esta versión no utiliza vectores ni embeddings, por lo que no demuestra aislamiento de un índice. MCP autoriza cada artículo antes de devolverlo y de construir la evidencia para el modelo. |

La documentación del repositorio también relaciona controles con supply chain, salida insegura, filtración del prompt, desinformación, consumo sin límite y OWASP API Security. El detalle actualizado está en el README; esta tabla mantiene el recorte temático del documento de referencia.

## 3 Mecanismos de mitigación y protección

### Identidad y autenticación

El navegador inicia Authorization Code con PKCE S256 contra Keycloak. El BFF comprueba `state`, `nonce`, firma, emisor, audiencia, expiración y coincidencia de sujeto entre los tokens. Los access y refresh tokens quedan del lado servidor. El navegador conserva una cookie de sesión opaca `HttpOnly`, y el BFF aplica protección CSRF y validación de origen en las operaciones de escritura.

### Autorización por herramienta y recurso

El BFF entrega a MCP el access token de la persona. MCP valida firma, issuer, audiencia `mcp-support`, cliente autorizado `agent-bff`, vencimiento y scopes. Las herramientas de lectura requieren `support:read`; la de escritura también verifica `support:write`. Para cada artículo, ticket o creación, el servidor obtiene los atributos del recurso y consulta OPA. La política deniega por defecto y una falla de OPA se convierte en denegación.

El realm de demostración agrega la audiencia `mcp-support` mediante la configuración de cliente en Keycloak. Esta PoC no ejecuta un intercambio de tokens ni el parámetro OAuth `resource` de extremo a extremo. Publica metadata de Protected Resource MCP, pero el BFF es quien realiza el login OIDC y adquiere el token.

### Consentimiento y confirmación humana

El consentimiento para usar herramientas de lectura y el consentimiento para enviar la consulta a Ollama son controles independientes, revocables durante la sesión. La creación del ticket exige revisar y confirmar una tarjeta editable. La prueba de aprobación tiene vencimiento y queda ligada al sujeto, sesión, acción, resumen y descripción; MCP verifica esa prueba y consulta OPA antes de escribir.

### Privacidad, límites y auditoría

El modelo local sólo recibe la consulta y la evidencia autorizada si la persona habilita ese procesamiento. Sin consentimiento o si Ollama no responde, se usa una respuesta determinística local. El chat limita el mensaje a 1.200 caracteres y a 20 por minuto por sesión; la búsqueda devuelve como máximo cinco artículos. Los logs de MCP registran sujeto, herramienta, recurso y decisión, sin tokens, prompts ni descripciones de tickets.

## 4 Diseño del agente y del servidor MCP

El chat funciona como BFF: conserva sesión y tokens, solicita consentimiento, valida propuestas del modelo y presenta resultados o borradores de acción. El servidor MCP es un resource server independiente que revalida la identidad. OPA mantiene las reglas de autorización separadas de la lógica de herramientas.

| Componente | Responsabilidad en la PoC |
|---|---|
| Chat React y BFF FastAPI | Interfaz conversacional; login y sesión; consentimiento; validación de argumentos; límite de mensajes; presentación de ticket pendiente y confirmación. |
| Keycloak | Proveedor OIDC local; realm `support-poc`; usuarios y roles sintéticos; tokens con audiencia y scopes de soporte. |
| Servidor MCP | Streamable HTTP con tres herramientas tipadas: `search_kb`, `get_my_ticket` y `create_support_ticket`. Verifica JWT, scopes y prueba de aprobación. |
| OPA | Punto de decisión de políticas. Recibe sujeto, acción y atributos del recurso; aplica reglas de artículos, tickets y alta de tickets. |
| SQLite | Artículos públicos e internos, artículo en cuarentena y tickets ficticios de Alice (`T-102`) y Bob (`T-203`). |
| Ollama y Qwen3.5:2b | Modelo local dentro de Compose. Sólo redacta o propone una herramienta habilitada; no recibe tokens ni decide permisos. |

## 5 Roles y permisos de demostración

| Perfil | Acceso previsto |
|---|---|
| Colaborador (`employee`) | Artículos públicos y tickets propios. Puede preparar y confirmar un ticket nuevo dirigido a la cola fija `network`, sujeto a autorización OPA. |
| Soporte L1 (`support_l1`) | Artículos públicos y artículos internos de las colas asignadas; tickets propios o de una cola asignada. Puede preparar y confirmar tickets, siempre sujeto a OPA. |

Keycloak autentica y entrega claims; OPA decide cada recurso. El rol por sí solo no reemplaza la comprobación de propiedad, cola, clasificación, aprobación ni estado.

## 6 Escenarios de demostración

| Caso | Interacción | Resultado esperado |
|---|---|---|
| **A Consulta válida** | Alice pregunta cómo resolver una VPN en Windows y autoriza la lectura de artículos. | OPA permite sólo artículos públicos aprobados. El chat cita fuentes como `KB-VPN-WIN`; la evidencia autorizada puede pasar a Qwen si el consentimiento del modelo está activo. |
| **B Inyección indirecta** | Se busca el artículo de prueba `KB-QUARANTINE`, cuyo contenido contiene instrucciones maliciosas. | El registro no aprobado se excluye de la búsqueda y no aparece como fuente. Este escenario prueba la cuarentena, no una defensa completa frente a una inyección dentro de contenido aprobado. |
| **C Acceso a ticket ajeno** | Alice consulta `T-203`, que pertenece a Bob. | OPA deniega la lectura. El chat presenta el mismo mensaje que para un ticket inexistente y no revela resumen, descripción ni existencia. |
| **D Acceso por asignación** | Soporte L1 consulta un ticket de la cola `network` o el artículo interno de clasificación. | OPA permite la lectura si la cola está asignada. Alice, con rol `employee`, no puede leer el artículo interno. |
| **E Acción con impacto** | El agente prepara un ticket o recibe una propuesta de herramienta no incluida en la allowlist. | El ticket queda como borrador hasta que la persona revisa y confirma. MCP exige prueba válida y OPA vuelve a autorizar. Una herramienta como cambio de rol no existe y el BFF rechaza la propuesta. |

## 7 Guion para la demo

Duración sugerida: 12 a 15 minutos, más la descarga inicial del modelo. Se usa localhost y únicamente información sintética.

### Preparación

- Requisitos: Docker y Docker Compose.
- En la raíz del repositorio, ejecutar `cp .env.example .env` y luego `docker compose up -d --build`.
- Comprobar el estado con `docker compose ps`. En el primer arranque, Compose descarga imágenes y el modelo `qwen3.5:2b` (aprox. 2,7–3,1 GB); esperar a que termine `ollama-model`.
- Abrir `http://localhost:8000`. Keycloak local se publica en `http://localhost:8080` para la consola y el realm de demostración.

| Usuario | Contraseña local | Perfil para el recorrido |
|---|---|---|
| `alice` | `alice-demo-pass` | Colaboradora; ticket propio `T-102`. |
| `bob` | `bob-demo-pass` | Colaborador; ticket propio `T-203`. |
| `soporte` | `soporte-demo-pass` | Soporte L1; cola asignada `network`. |

Las contraseñas son credenciales sintéticas para el entorno local y están versionadas para facilitar la demo. No deben reutilizarse ni exponerse en un despliegue real.

### Recorrido paso a paso

1. Iniciar sesión como `alice`. Activar el consentimiento de modelo local desde “Permisos de sesión”. Explicar que el modelo recibe la consulta y evidencia autorizada, nunca el token.
2. Preguntar “No puedo conectarme a la VPN desde Windows”. Autorizar `search_kb` cuando aparezca la tarjeta de permiso. Mostrar la respuesta y las fuentes aprobadas; distinguir el consentimiento de herramienta del consentimiento del modelo.
3. Consultar `T-102` y luego `T-203`, autorizando la herramienta de lectura. Verificar que Alice obtiene su ticket y no puede distinguir el ticket de Bob de un identificador inexistente.
4. Pedir abrir un ticket por conectividad. Editar el resumen o la descripción en la tarjeta y elegir **Cancelar** para no escribir en la base. Si se quiere demostrar la escritura, revisar y seleccionar **Confirmar creación** y mostrar la respuesta de éxito.
5. Cerrar sesión e ingresar como `soporte`. Consultar `T-203` y el artículo interno de clasificación para demostrar el permiso por asignación de cola. Alice no debe ver ese artículo.
6. Buscar “artículo en cuarentena”. Confirmar que `KB-QUARANTINE` no aparece entre las fuentes.

### Observabilidad y prueba de falla cerrada

Para observar invocaciones y decisiones de política, ejecutar `docker compose logs --tail=50 mcp opa` y buscar los eventos `tool_invocation` y `tool_authorization`.

Como variante opcional, con la aplicación activa, ejecutar `docker compose stop opa`, intentar una lectura y verificar que la operación falla cerrada. Restaurar el entorno con `docker compose start opa`. OPA y Ollama no publican puertos en el host; MCP se limita a loopback para facilitar la inspección local.

## 8 Límites y trabajo pendiente

- El realm usa `start-dev`, HTTP local, cuentas demo y secretos de ejemplo. No exponer el Compose fuera de una máquina de desarrollo.
- Sesiones, consentimientos y rate limit son memoria de una instancia; reiniciar el BFF los elimina y no existe control distribuido.
- No hay ingestión con procedencia y revisión formal de conocimiento, RAG vectorial, modelo entrenado, telemetría central ni retención de auditoría.
- La autorización del consentimiento UI la aplica el BFF antes de la herramienta; MCP y OPA aplican los controles de identidad y acceso al recurso independientemente.
- Para producción harían falta TLS, secretos y credenciales propios, configuración productiva de Keycloak, persistencia de sesiones, rate limit distribuido, pruebas adversariales, escaneo de dependencias y evaluación de recuperación de datos.

## 9 Conclusión

La PoC hace visible una separación importante para un chat de soporte con agente: Keycloak prueba quién es la persona, MCP aplica autenticación en el servidor de herramientas y OPA decide a qué recurso puede acceder. El modelo propone; el BFF valida; la interfaz obtiene la confirmación de escritura; y MCP vuelve a autorizar antes de guardar.

El recorrido demuestra consultas autorizadas, aislamiento entre tickets, acceso interno por asignación, cuarentena de un artículo contaminado, confirmación humana y denegación ante una falla de OPA. Los resultados sirven como demostración técnica de esos controles en un entorno local; no sustituyen una evaluación de seguridad ni la preparación de un despliegue productivo.

## Referencias

1. Documento base, [“Seguridad en Inteligencia Artificial: Vulnerabilidades OWASP y mecanismos de mitigación”](https://docs.google.com/document/d/1B5O8RHngPjX8MWVWJvreL8JFbL_Kigg0T02-btIVq1k/edit).
2. OWASP GenAI Security Project, [Top 10 for LLM Applications 2025](https://genai.owasp.org/initiatives/top-10-for-llm-and-genai/).
3. OWASP GenAI Security Project, [Top 10 for LLM Applications 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/).
4. Model Context Protocol, [especificación de autorización y metadata de recursos protegidos](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
5. Keycloak, [documentación de token exchange y scopes/audiences](https://www.keycloak.org/securing-apps/token-exchange).
6. Open Policy Agent, [documentación de despliegue y modelo PDP/PEP](https://www.openpolicyagent.org/docs/deploy).
7. OWASP API Security Project, [API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/).
